package router

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	"github.com/malvinpratama/iam-go-libs/config"
)

// oidcIssuer is the OIDC issuer URL: the OIDC_ISSUER env if set, else derived
// from the incoming request (so the discovery doc is self-consistent).
func oidcIssuer(c *gin.Context) string {
	if v := config.Getenv("OIDC_ISSUER", ""); v != "" {
		return strings.TrimRight(v, "/")
	}
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

// oidcDiscovery serves the OpenID Connect discovery document.
func (h *handlers) oidcDiscovery(c *gin.Context) {
	iss := oidcIssuer(c)
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"end_session_endpoint":                  iss + "/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// jwks serves the JSON Web Key Set (public RS256 signing keys) from the auth service.
func (h *handlers) jwks(c *gin.Context) {
	res, err := h.c.Auth.GetJwks(c.Request.Context(), &authv1.GetJwksRequest{})
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "jwks unavailable"})
		return
	}
	keys := make([]gin.H, 0, len(res.GetKeys()))
	for _, k := range res.GetKeys() {
		keys = append(keys, gin.H{
			"kty": k.GetKty(), "use": k.GetUse(), "alg": k.GetAlg(),
			"kid": k.GetKid(), "n": k.GetN(), "e": k.GetE(),
		})
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}
