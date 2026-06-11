package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
)

// ── 2FA ─────────────────────────────────────────────────────

// loginTotp completes a login that returned mfa_required.
func (h *handlers) loginTotp(c *gin.Context) {
	var body struct {
		MfaToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tp, err := h.c.Auth.LoginTotp(forward(c), &authv1.LoginTotpRequest{MfaToken: body.MfaToken, Code: body.Code})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, tokenPairJSON(tp))
}

// totpStatus reports whether 2FA is active for the caller.
func (h *handlers) totpStatus(c *gin.Context) {
	res, err := h.c.Auth.GetTotpStatus(forward(c), &authv1.GetTotpStatusRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": res.GetEnabled()})
}

// enrollTotp starts 2FA enrollment for the caller (returns secret + recovery codes).
func (h *handlers) enrollTotp(c *gin.Context) {
	res, err := h.c.Auth.EnrollTotp(forward(c), &authv1.EnrollTotpRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"secret":         res.GetSecret(),
		"otpauth_uri":    res.GetOtpauthUri(),
		"recovery_codes": res.GetRecoveryCodes(),
	})
}

func (h *handlers) activateTotp(c *gin.Context) {
	var body struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := h.c.Auth.ActivateTotp(forward(c), &authv1.ActivateTotpRequest{Code: body.Code}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *handlers) disableTotp(c *gin.Context) {
	var body struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := h.c.Auth.DisableTotp(forward(c), &authv1.DisableTotpRequest{Code: body.Code}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ── API keys ────────────────────────────────────────────────

func (h *handlers) createApiKey(c *gin.Context) {
	var body struct {
		Name       string   `json:"name" binding:"required"`
		Scopes     []string `json:"scopes"`
		TTLSeconds int64    `json:"ttl_seconds"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := h.c.Auth.CreateApiKey(forward(c), &authv1.CreateApiKeyRequest{
		Name: body.Name, Scopes: body.Scopes, TtlSeconds: body.TTLSeconds,
	})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"secret": res.GetSecret(), "key": apiKeyJSON(res.GetKey())})
}

func (h *handlers) listApiKeys(c *gin.Context) {
	res, err := h.c.Auth.ListApiKeys(forward(c), &authv1.ListApiKeysRequest{})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	keys := make([]gin.H, 0, len(res.GetKeys()))
	for _, k := range res.GetKeys() {
		keys = append(keys, apiKeyJSON(k))
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

func (h *handlers) revokeApiKey(c *gin.Context) {
	if _, err := h.c.Auth.RevokeApiKey(forward(c), &authv1.RevokeApiKeyRequest{Id: c.Param("id")}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func apiKeyJSON(k *authv1.ApiKey) gin.H {
	return gin.H{
		"id":           k.GetId(),
		"name":         k.GetName(),
		"scopes":       k.GetScopes(),
		"created_at":   k.GetCreatedAt(),
		"expires_at":   k.GetExpiresAt(),
		"last_used_at": k.GetLastUsedAt(),
	}
}

// ── soft-delete restore ─────────────────────────────────────

func (h *handlers) restoreUser(c *gin.Context) {
	if _, err := h.c.Auth.RestoreUser(forward(c), &authv1.RestoreUserRequest{UserId: c.Param("id")}); err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ── bulk operations ─────────────────────────────────────────

func (h *handlers) assignRoleBulk(c *gin.Context) {
	var body struct {
		UserIDs   []string `json:"user_ids" binding:"required"`
		ProjectID string   `json:"project_id"` // empty = tenant-wide
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := h.c.Auth.AssignRoleBulk(forward(c), &authv1.AssignRoleBulkRequest{
		RoleName: c.Param("name"), UserIds: body.UserIDs, ProjectId: body.ProjectID,
	})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"assigned": res.GetAssigned(), "failed": res.GetFailed()})
}
