// Package middleware provides authentication and authorization for the gateway.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	"github.com/malvinpratama/iam-go-libs/grpcutil"
)

const identityKey = "identity"

// Authenticator validates the bearer token against the Auth service.
type Authenticator struct {
	auth authv1.AuthServiceClient
}

// NewAuthenticator builds an Authenticator.
func NewAuthenticator(auth authv1.AuthServiceClient) *Authenticator {
	return &Authenticator{auth: auth}
}

// Require ensures the request carries a valid access token and stores the
// resolved identity in the gin context.
func (a *Authenticator) Require() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearer(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		res, err := a.auth.ValidateToken(c.Request.Context(), &authv1.ValidateTokenRequest{AccessToken: token})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}
		c.Set(identityKey, grpcutil.Identity{
			UserID:      res.GetUserId(),
			Email:       res.GetEmail(),
			Roles:       res.GetRoles(),
			Permissions: res.GetPermissions(),
		})
		c.Next()
	}
}

// RequirePermission ensures the authenticated caller holds the given permission.
func RequirePermission(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := IdentityOf(c)
		if !hasPermission(id, perm) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "permission denied: " + perm})
			return
		}
		c.Next()
	}
}

// IdentityOf returns the identity stored by Require (zero value if absent).
func IdentityOf(c *gin.Context) grpcutil.Identity {
	if v, ok := c.Get(identityKey); ok {
		if id, ok := v.(grpcutil.Identity); ok {
			return id
		}
	}
	return grpcutil.Identity{}
}

func hasPermission(id grpcutil.Identity, perm string) bool {
	for _, p := range id.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

func bearer(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
