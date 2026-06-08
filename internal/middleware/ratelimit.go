package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter is a simple in-memory fixed-window limiter keyed by client IP.
// Suitable for a single-instance demo; use Redis/a gateway for multi-instance.
type RateLimiter struct {
	mu       sync.Mutex
	hits     map[string]*ipWindow
	limit    int
	window   time.Duration
	lastSwip time.Time
}

type ipWindow struct {
	count int
	reset time.Time
}

// BodyLimit caps the request body size to guard against memory-exhaustion DoS.
func BodyLimit(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		c.Next()
	}
}

// NewRateLimiter allows `limit` requests per `window` per IP.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{hits: make(map[string]*ipWindow), limit: limit, window: window}
}

// Limit is gin middleware enforcing the per-IP rate limit.
func (rl *RateLimiter) Limit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()

		rl.mu.Lock()
		rl.sweep(now)
		w, ok := rl.hits[ip]
		if !ok || now.After(w.reset) {
			w = &ipWindow{count: 0, reset: now.Add(rl.window)}
			rl.hits[ip] = w
		}
		w.count++
		over := w.count > rl.limit
		retry := int(time.Until(w.reset).Seconds())
		rl.mu.Unlock()

		if over {
			c.Header("Retry-After", itoa(retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded, slow down"})
			return
		}
		c.Next()
	}
}

// sweep drops expired windows occasionally to bound memory. Caller holds mu.
func (rl *RateLimiter) sweep(now time.Time) {
	if now.Sub(rl.lastSwip) < rl.window {
		return
	}
	rl.lastSwip = now
	for ip, w := range rl.hits {
		if now.After(w.reset) {
			delete(rl.hits, ip)
		}
	}
}

func itoa(n int) string {
	if n < 0 {
		n = 0
	}
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
