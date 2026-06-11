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
