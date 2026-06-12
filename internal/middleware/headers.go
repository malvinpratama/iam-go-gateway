package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders sets conservative response headers on every request: stop MIME
// sniffing, forbid framing (clickjacking guard for the OIDC login/consent HTML),
// and trim referrer leakage. HSTS is added only when the edge terminated TLS
// (Cloudflare/Traefik forward X-Forwarded-Proto=https) so local HTTP dev is
// unaffected.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}
