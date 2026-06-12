// Package router wires the REST endpoints to the gRPC backend services.
package router

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	userv1 "github.com/malvinpratama/iam-go-contracts/gen/user/v1"
	gateway "github.com/malvinpratama/iam-go-gateway"
	"github.com/malvinpratama/iam-go-gateway/internal/client"
	"github.com/malvinpratama/iam-go-gateway/internal/middleware"
	"github.com/malvinpratama/iam-go-libs/config"
	"github.com/malvinpratama/iam-go-libs/grpcutil"
)

// New builds the gin engine with all routes registered.
func New(clients *client.Clients, log *slog.Logger) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(otelgin.Middleware("gateway")) // trace each request + extract context
	r.Use(middleware.RequestID())        // correlation id
	r.Use(middleware.Observability(log)) // metrics + access log
	r.Use(middleware.BodyLimit(1 << 20)) // 1 MiB max request body (DoS guard)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Interactive API docs (public): Swagger UI at /docs, spec at /openapi.yaml.
	r.GET("/openapi.yaml", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/yaml", gateway.OpenAPISpec)
	})
	if ui, err := fs.Sub(gateway.SwaggerUI, "swaggerui"); err == nil {
		r.StaticFS("/docs", http.FS(ui))
	}

	authn := middleware.NewAuthenticator(clients.Auth)
	h := &handlers{c: clients}

	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	// OIDC discovery + JWKS (public) — lets external relying parties verify tokens.
	r.GET("/.well-known/openid-configuration", h.oidcDiscovery)
	r.GET("/.well-known/jwks.json", h.jwks)

	// OIDC Authorization Code flow (browser): login form, consent, code issuance.
	r.GET("/authorize", h.authorize)
	r.POST("/authorize/login", h.authorizeLogin)
	r.POST("/authorize/totp", h.authorizeTotp) // 2FA step of the browser login
	r.POST("/authorize/consent", h.authorizeConsent)
	r.POST("/token", h.token)
	r.GET("/logout", h.oidcLogout) // OIDC RP-initiated end-session

	// Public auth endpoints — rate limited per IP to slow brute-force. Redis-backed
	// (shared across replicas) when REDIS_URL is set, else in-memory. Tunable via
	// env (defaults 60 req / 60s); 0 disables.
	authLimit := middleware.NewAuthLimiter(
		config.GetenvInt("AUTH_RATE_LIMIT", 60),
		config.GetenvDuration("AUTH_RATE_WINDOW_SECONDS", 60),
		log,
	)
	r.POST("/auth/register", authLimit, h.register)
	r.POST("/auth/login", authLimit, h.login)
	r.POST("/auth/login/totp", authLimit, h.loginTotp) // complete a 2FA login
	r.POST("/auth/refresh", authLimit, h.refresh)
	r.POST("/auth/verify-email/request", authLimit, h.requestEmailVerification)
	r.POST("/auth/verify-email", authLimit, h.verifyEmail)
	r.POST("/auth/password-reset/request", authLimit, h.requestPasswordReset)
	r.POST("/auth/password-reset", authLimit, h.resetPassword)

	// Authenticated endpoints.
	auth := r.Group("/")
	auth.Use(authn.Require())
	{
		auth.POST("/auth/logout", h.logout)
		auth.GET("/me", h.getIdentity)
		auth.GET("/me/memberships", h.listMemberships) // M6: tenants the caller belongs to
		auth.POST("/auth/switch", h.switchTenant)      // M6: re-issue token for another tenant
		// M6.4: tenant / project / member administration.
		auth.POST("/tenants", middleware.RequirePermission("tenant:write"), h.createTenant)
		auth.GET("/tenants", middleware.RequirePermission("tenant:read"), h.listTenants)
		auth.POST("/projects", middleware.RequirePermission("project:write"), h.createProject)
		auth.GET("/projects", middleware.RequirePermission("project:read"), h.listProjects)
		auth.GET("/members", middleware.RequirePermission("member:read"), h.listMembers)
		auth.POST("/members", middleware.RequirePermission("member:write"), h.addMember)
		auth.DELETE("/members/:userId", middleware.RequirePermission("member:write"), h.removeMember)
		auth.GET("/userinfo", h.userinfo) // OIDC UserInfo
		// 2FA (self-service)
		auth.GET("/auth/2fa", h.totpStatus)
		auth.POST("/auth/2fa/enroll", h.enrollTotp)
		auth.POST("/auth/2fa/activate", h.activateTotp)
		auth.POST("/auth/2fa/disable", h.disableTotp)
		// API keys (self-service): scoped programmatic credentials
		auth.POST("/api-keys", h.createApiKey)
		auth.GET("/api-keys", h.listApiKeys)
		auth.DELETE("/api-keys/:id", h.revokeApiKey)
		// Restore a soft-deleted user (admin)
		auth.POST("/users/:id/restore", middleware.RequirePermission("user:delete"), h.restoreUser)
		auth.POST("/oauth/clients", middleware.RequirePermission("role:write"), h.registerClient)
		auth.GET("/users/me", h.getMe)
		auth.GET("/permissions", middleware.RequirePermission("role:read"), h.listPermissions)
		auth.GET("/audit", middleware.RequirePermission("audit:read"), h.listAudit)
		auth.GET("/users/:id", middleware.RequirePermission("user:read"), h.getUser)
		auth.GET("/users", middleware.RequirePermission("user:read"), h.listUsers)
		auth.PATCH("/users/:id", h.updateUser) // self or profile:write — checked inline
		auth.DELETE("/users/:id", middleware.RequirePermission("user:delete"), h.deleteUser)
		auth.GET("/roles", middleware.RequirePermission("role:read"), h.listRoles)
		auth.POST("/roles", middleware.RequirePermission("role:write"), h.createRole)
		auth.PATCH("/roles/:name", middleware.RequirePermission("role:write"), h.updateRole)
		auth.DELETE("/roles/:name", middleware.RequirePermission("role:write"), h.deleteRole)
		auth.POST("/roles/:name/permissions", middleware.RequirePermission("role:write"), h.grantPermission)
		auth.DELETE("/roles/:name/permissions/:perm", middleware.RequirePermission("role:write"), h.revokePermission)
		auth.GET("/users/:id/roles", middleware.RequirePermission("role:read"), h.getUserRoleAssignments)
		auth.POST("/users/:id/roles", middleware.RequirePermission("role:assign"), h.assignRole)
		auth.POST("/roles/:name/assignments", middleware.RequirePermission("role:assign"), h.assignRoleBulk)
		auth.DELETE("/users/:id/roles/:role", middleware.RequirePermission("role:assign"), h.revokeRole)
	}
	return r
}

type handlers struct {
	c *client.Clients
}

// ── auth ────────────────────────────────────────────────────

func (h *handlers) register(c *gin.Context) {
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	reg, err := h.c.Auth.Register(forward(c), &authv1.RegisterRequest{Email: body.Email, Password: body.Password})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	// Profile creation is now driven asynchronously by a UserRegistered event
	// (transactional outbox in auth → NATS → user service). The gateway no
	// longer calls the user service here; GET /users/me heals lazily if a read
	// arrives before the event is processed.
	c.JSON(http.StatusCreated, gin.H{"user_id": reg.GetUserId(), "email": reg.GetEmail()})
}

func (h *handlers) login(c *gin.Context) {
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tp, err := h.c.Auth.Login(forward(c), &authv1.LoginRequest{Email: body.Email, Password: body.Password})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, tokenPairJSON(tp))
}

func (h *handlers) refresh(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tp, err := h.c.Auth.Refresh(forward(c), &authv1.RefreshRequest{RefreshToken: body.RefreshToken})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, tokenPairJSON(tp))
}

func (h *handlers) logout(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Pass the access token too so the auth service can denylist it (by jti).
	access := bearerToken(c)
	if _, err := h.c.Auth.Logout(forward(c), &authv1.LogoutRequest{RefreshToken: body.RefreshToken, AccessToken: access}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// ── account recovery & verification (v0.2) ──────────────────

func (h *handlers) requestEmailVerification(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := h.c.Auth.RequestEmailVerification(c.Request.Context(), &authv1.EmailRequest{Email: body.Email})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, devTokenJSON(res))
}

func (h *handlers) verifyEmail(c *gin.Context) {
	var body struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := h.c.Auth.VerifyEmail(c.Request.Context(), &authv1.TokenRequest{Token: body.Token}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *handlers) requestPasswordReset(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := h.c.Auth.RequestPasswordReset(c.Request.Context(), &authv1.EmailRequest{Email: body.Email})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, devTokenJSON(res))
}

func (h *handlers) resetPassword(c *gin.Context) {
	var body struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := h.c.Auth.ResetPassword(c.Request.Context(), &authv1.ResetPasswordRequest{Token: body.Token, NewPassword: body.NewPassword}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func devTokenJSON(res *authv1.DevTokenResponse) gin.H {
	out := gin.H{"success": res.GetSuccess()}
	if res.GetDevToken() != "" {
		out["dev_token"] = res.GetDevToken() // present only in non-production
	}
	return out
}

// ── audit (v0.2) ────────────────────────────────────────────

func (h *handlers) listAudit(c *gin.Context) {
	var q struct {
		Limit int32 `form:"limit"`
	}
	_ = c.ShouldBindQuery(&q)
	res, err := h.c.Auth.ListAuditEvents(forward(c), &authv1.ListAuditEventsRequest{Limit: q.Limit})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	events := make([]gin.H, 0, len(res.GetEvents()))
	for _, e := range res.GetEvents() {
		events = append(events, gin.H{
			"id": e.GetId(), "actor_id": e.GetActorId(), "actor_email": e.GetActorEmail(),
			"action": e.GetAction(), "target": e.GetTarget(), "detail": e.GetDetail(), "created_at": e.GetCreatedAt(),
		})
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

// ── users ───────────────────────────────────────────────────

func (h *handlers) getMe(c *gin.Context) {
	id := middleware.IdentityOf(c)
	p, err := h.c.User.GetProfile(forward(c), &userv1.GetProfileRequest{UserId: id.UserID})
	if err == nil {
		c.JSON(http.StatusOK, profileJSON(p))
		return
	}
	// Heal ghost users: if registration created the identity but not the profile,
	// create it now (idempotent) instead of returning 404.
	if status.Code(err) == codes.NotFound {
		display := id.Email
		if i := strings.Index(id.Email, "@"); i > 0 {
			display = id.Email[:i]
		}
		if created, cerr := h.c.User.CreateProfile(forward(c), &userv1.CreateProfileRequest{UserId: id.UserID, DisplayName: display}); cerr == nil {
			c.JSON(http.StatusOK, profileJSON(created))
			return
		}
	}
	writeGRPCError(c, err)
}

// getIdentity returns the caller's own identity, roles and permissions.
func (h *handlers) getIdentity(c *gin.Context) {
	id := middleware.IdentityOf(c)
	c.JSON(http.StatusOK, gin.H{
		"user_id":     id.UserID,
		"email":       id.Email,
		"roles":       id.Roles,
		"permissions": id.Permissions,
	})
}

// listPermissions returns every permission defined in the system.
func (h *handlers) listPermissions(c *gin.Context) {
	res, err := h.c.Auth.ListPermissions(forward(c), &authv1.ListPermissionsRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	perms := make([]gin.H, 0, len(res.GetPermissions()))
	for _, p := range res.GetPermissions() {
		perms = append(perms, gin.H{"id": p.GetId(), "name": p.GetName(), "description": p.GetDescription()})
	}
	c.JSON(http.StatusOK, gin.H{"permissions": perms})
}

func (h *handlers) getUser(c *gin.Context) {
	id := c.Param("id")
	// Tenant-scope the lookup: a profile is only visible to admins of a tenant the
	// target belongs to. ListMembers is already scoped to the caller's active
	// tenant, so an id outside it returns 404 rather than leaking another tenant's
	// user (its very existence included).
	members, err := h.c.Auth.ListMembers(forward(c), &authv1.ListMembersRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	member := false
	for _, m := range members.GetMembers() {
		if m.GetUserId() == id {
			member = true
			break
		}
	}
	if !member {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	p, err := h.c.User.GetProfile(forward(c), &userv1.GetProfileRequest{UserId: id})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, profileJSON(p))
}

// listUsers returns the active tenant's directory: its members (from auth)
// joined with their profiles (one batch GetProfiles call — no N+1). This keeps
// the user list tenant-scoped so a tenant admin never sees other tenants' users.
func (h *handlers) listUsers(c *gin.Context) {
	ctx := forward(c)
	members, err := h.c.Auth.ListMembers(ctx, &authv1.ListMembersRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	ids := make([]string, 0, len(members.GetMembers()))
	emailByID := make(map[string]string, len(members.GetMembers()))
	statusByID := make(map[string]string, len(members.GetMembers()))
	for _, m := range members.GetMembers() {
		ids = append(ids, m.GetUserId())
		emailByID[m.GetUserId()] = m.GetEmail()
		statusByID[m.GetUserId()] = m.GetStatus()
	}
	profByID := make(map[string]*userv1.Profile, len(ids))
	if len(ids) > 0 {
		profs, err := h.c.User.GetProfiles(ctx, &userv1.GetProfilesRequest{UserIds: ids})
		if err != nil {
			writeGRPCError(c, err)
			return
		}
		for _, p := range profs.GetProfiles() {
			profByID[p.GetUserId()] = p
		}
	}
	out := make([]gin.H, 0, len(ids))
	for _, id := range ids {
		row := gin.H{"user_id": id, "email": emailByID[id], "status": statusByID[id]}
		if p := profByID[id]; p != nil {
			row["display_name"] = p.GetDisplayName()
			row["bio"] = p.GetBio()
			row["created_at"] = p.GetCreatedAt()
		}
		out = append(out, row)
	}
	c.JSON(http.StatusOK, gin.H{"profiles": out, "total": len(out), "page": 1, "page_size": len(out)})
}

func (h *handlers) updateUser(c *gin.Context) {
	id := middleware.IdentityOf(c)
	target := c.Param("id")
	// Own profile needs only authentication (profile:write); editing SOMEONE
	// ELSE's profile requires the admin-only user:write permission.
	if target == id.UserID {
		if !contains(id.Permissions, "profile:write") {
			c.JSON(http.StatusForbidden, gin.H{"error": "permission denied: profile:write"})
			return
		}
	} else if !contains(id.Permissions, "user:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "permission denied: user:write"})
		return
	}
	var body struct {
		DisplayName *string `json:"display_name"`
		Bio         *string `json:"bio"`
		AvatarURL   *string `json:"avatar_url"`
		Phone       *string `json:"phone"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p, err := h.c.User.UpdateProfile(forward(c), &userv1.UpdateProfileRequest{
		UserId:      target,
		DisplayName: body.DisplayName,
		Bio:         body.Bio,
		AvatarUrl:   body.AvatarURL,
		Phone:       body.Phone,
	})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, profileJSON(p))
}

func (h *handlers) deleteUser(c *gin.Context) {
	target := c.Param("id")
	hard := c.Query("hard") == "true"
	// Soft-delete by default (recoverable via /users/:id/restore); ?hard=true
	// removes the identity permanently. The matching profile is updated
	// asynchronously via a UserDeleted event.
	if _, err := h.c.Auth.DeleteUser(forward(c), &authv1.DeleteUserRequest{UserId: target, Hard: hard}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "hard": hard})
}

// ── RBAC ────────────────────────────────────────────────────

func (h *handlers) listRoles(c *gin.Context) {
	res, err := h.c.Auth.ListRoles(forward(c), &authv1.ListRolesRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	roles := make([]gin.H, 0, len(res.GetRoles()))
	for _, r := range res.GetRoles() {
		roles = append(roles, gin.H{"id": r.GetId(), "name": r.GetName(), "description": r.GetDescription(), "permissions": r.GetPermissions()})
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

func (h *handlers) createRole(c *gin.Context) {
	var body struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	role, err := h.c.Auth.CreateRole(forward(c), &authv1.CreateRoleRequest{Name: body.Name, Description: body.Description})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": role.GetId(), "name": role.GetName(), "description": role.GetDescription()})
}

func (h *handlers) updateRole(c *gin.Context) {
	var body struct {
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	role, err := h.c.Auth.UpdateRole(forward(c), &authv1.UpdateRoleRequest{Name: c.Param("name"), Description: body.Description})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": role.GetId(), "name": role.GetName(), "description": role.GetDescription()})
}

func (h *handlers) deleteRole(c *gin.Context) {
	if _, err := h.c.Auth.DeleteRole(forward(c), &authv1.DeleteRoleRequest{Name: c.Param("name")}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *handlers) grantPermission(c *gin.Context) {
	var body struct {
		Permission string `json:"permission" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := h.c.Auth.GrantPermission(forward(c), &authv1.GrantPermissionRequest{RoleName: c.Param("name"), PermissionName: body.Permission}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *handlers) revokePermission(c *gin.Context) {
	if _, err := h.c.Auth.RevokePermission(forward(c), &authv1.RevokePermissionRequest{RoleName: c.Param("name"), PermissionName: c.Param("perm")}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *handlers) assignRole(c *gin.Context) {
	var body struct {
		Role      string `json:"role" binding:"required"`
		ProjectID string `json:"project_id"` // empty = tenant-wide
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := h.c.Auth.AssignRole(forward(c), &authv1.AssignRoleRequest{UserId: c.Param("id"), RoleName: body.Role, ProjectId: body.ProjectID}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *handlers) revokeRole(c *gin.Context) {
	// ?project_id=… selects the project-scoped assignment; omit for tenant-wide.
	if _, err := h.c.Auth.RevokeRole(forward(c), &authv1.RevokeRoleRequest{UserId: c.Param("id"), RoleName: c.Param("role"), ProjectId: c.Query("project_id")}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// getUserRoleAssignments lists a user's role assignments in the active tenant
// (role + project scope), so the console can show + revoke them precisely.
func (h *handlers) getUserRoleAssignments(c *gin.Context) {
	res, err := h.c.Auth.GetUserRoleAssignments(forward(c), &authv1.GetUserRoleAssignmentsRequest{UserId: c.Param("id")})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	out := make([]gin.H, 0, len(res.GetAssignments()))
	for _, a := range res.GetAssignments() {
		out = append(out, gin.H{"role": a.GetRole(), "project_id": a.GetProjectId(), "project_slug": a.GetProjectSlug()})
	}
	c.JSON(http.StatusOK, gin.H{"assignments": out})
}

// ── helpers ─────────────────────────────────────────────────

// forward propagates the caller identity and correlation id to downstream gRPC
// services (trace context flows automatically via the otel client handler).
func forward(c *gin.Context) context.Context {
	ctx := grpcutil.Inject(c.Request.Context(), middleware.IdentityOf(c))
	return grpcutil.WithRequestID(ctx, c.GetString(middleware.RequestIDKey))
}

func tokenPairJSON(tp *authv1.TokenPair) gin.H {
	// 2FA: a password-only login may return a challenge instead of tokens.
	if tp.GetMfaRequired() {
		return gin.H{
			"mfa_required": true,
			"mfa_token":    tp.GetMfaToken(),
			"token_type":   tp.GetTokenType(),
		}
	}
	return gin.H{
		"access_token":  tp.GetAccessToken(),
		"refresh_token": tp.GetRefreshToken(),
		"expires_in":    tp.GetExpiresIn(),
		"token_type":    tp.GetTokenType(),
	}
}

func profileJSON(p *userv1.Profile) gin.H {
	return gin.H{
		"user_id":      p.GetUserId(),
		"display_name": p.GetDisplayName(),
		"bio":          p.GetBio(),
		"avatar_url":   p.GetAvatarUrl(),
		"phone":        p.GetPhone(),
		"created_at":   p.GetCreatedAt(),
		"updated_at":   p.GetUpdatedAt(),
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// writeGRPCError maps gRPC status codes to HTTP responses.
func writeGRPCError(c *gin.Context, err error) {
	st, _ := status.FromError(err)
	httpCode := http.StatusInternalServerError
	switch st.Code() {
	case codes.InvalidArgument:
		httpCode = http.StatusBadRequest
	case codes.Unauthenticated:
		httpCode = http.StatusUnauthorized
	case codes.PermissionDenied:
		httpCode = http.StatusForbidden
	case codes.NotFound:
		httpCode = http.StatusNotFound
	case codes.AlreadyExists:
		httpCode = http.StatusConflict
	case codes.FailedPrecondition:
		httpCode = http.StatusConflict
	}
	c.JSON(httpCode, gin.H{"error": st.Message()})
}
