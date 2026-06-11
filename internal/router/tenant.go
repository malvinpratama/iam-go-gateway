package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
)

// listMemberships returns the tenants the caller is an active member of.
func (h *handlers) listMemberships(c *gin.Context) {
	res, err := h.c.Auth.ListMyMemberships(forward(c), &authv1.ListMembershipsRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	out := make([]gin.H, 0, len(res.GetMemberships()))
	for _, m := range res.GetMemberships() {
		out = append(out, gin.H{
			"tenant_id": m.GetTenantId(), "tenant_slug": m.GetTenantSlug(),
			"tenant_name": m.GetTenantName(), "status": m.GetStatus(),
		})
	}
	c.JSON(http.StatusOK, gin.H{"memberships": out})
}

// switchTenant re-issues a token bound to another tenant/project the caller belongs to.
func (h *handlers) switchTenant(c *gin.Context) {
	var body struct {
		TenantID  string `json:"tenant_id" binding:"required"`
		ProjectID string `json:"project_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tp, err := h.c.Auth.SwitchTenant(forward(c), &authv1.SwitchTenantRequest{
		TenantId: body.TenantID, ProjectId: body.ProjectID,
	})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, tokenPairJSON(tp))
}

// ── M6.4: tenant / project / member administration ──────────

func tenantJSON(t *authv1.Tenant) gin.H {
	return gin.H{"id": t.GetId(), "slug": t.GetSlug(), "name": t.GetName(), "status": t.GetStatus()}
}

func projectJSON(p *authv1.Project) gin.H {
	return gin.H{"id": p.GetId(), "tenant_id": p.GetTenantId(), "slug": p.GetSlug(), "name": p.GetName()}
}

func memberJSON(m *authv1.Member) gin.H {
	return gin.H{"user_id": m.GetUserId(), "email": m.GetEmail(), "status": m.GetStatus()}
}

// createTenant provisions a new organization (the caller becomes its first member).
func (h *handlers) createTenant(c *gin.Context) {
	var body struct {
		Slug string `json:"slug" binding:"required"`
		Name string `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	t, err := h.c.Auth.CreateTenant(forward(c), &authv1.CreateTenantRequest{Slug: body.Slug, Name: body.Name})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusCreated, tenantJSON(t))
}

// listTenants returns every tenant (platform view).
func (h *handlers) listTenants(c *gin.Context) {
	res, err := h.c.Auth.ListTenants(forward(c), &authv1.ListTenantsRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	out := make([]gin.H, 0, len(res.GetTenants()))
	for _, t := range res.GetTenants() {
		out = append(out, tenantJSON(t))
	}
	c.JSON(http.StatusOK, gin.H{"tenants": out})
}

// createProject creates a project in the caller's active tenant.
func (h *handlers) createProject(c *gin.Context) {
	var body struct {
		Slug string `json:"slug" binding:"required"`
		Name string `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p, err := h.c.Auth.CreateProject(forward(c), &authv1.CreateProjectRequest{Slug: body.Slug, Name: body.Name})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusCreated, projectJSON(p))
}

// listProjects returns the projects in the caller's active tenant.
func (h *handlers) listProjects(c *gin.Context) {
	res, err := h.c.Auth.ListProjects(forward(c), &authv1.ListProjectsRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	out := make([]gin.H, 0, len(res.GetProjects()))
	for _, p := range res.GetProjects() {
		out = append(out, projectJSON(p))
	}
	c.JSON(http.StatusOK, gin.H{"projects": out})
}

// listMembers returns the members of the caller's active tenant.
func (h *handlers) listMembers(c *gin.Context) {
	res, err := h.c.Auth.ListMembers(forward(c), &authv1.ListMembersRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	out := make([]gin.H, 0, len(res.GetMembers()))
	for _, m := range res.GetMembers() {
		out = append(out, memberJSON(m))
	}
	c.JSON(http.StatusOK, gin.H{"members": out})
}

// addMember enrolls an existing user (by email) into the caller's active tenant.
func (h *handlers) addMember(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	m, err := h.c.Auth.AddMember(forward(c), &authv1.AddMemberRequest{Email: body.Email})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusCreated, memberJSON(m))
}

// removeMember removes a user from the caller's active tenant.
func (h *handlers) removeMember(c *gin.Context) {
	_, err := h.c.Auth.RemoveMember(forward(c), &authv1.RemoveMemberRequest{UserId: c.Param("userId")})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}
