package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Integration test: needs a Redis at $REDIS_URL (skipped otherwise). Verifies the
// shared limiter enforces the per-IP limit (the counter lives in Redis, so it
// holds across replicas).
func TestRedisLimiter(t *testing.T) {
	if os.Getenv("REDIS_URL") == "" {
		t.Skip("REDIS_URL not set")
	}
	gin.SetMode(gin.TestMode)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := gin.New()
	r.GET("/t", NewAuthLimiter(3, time.Minute, log), func(c *gin.Context) { c.Status(http.StatusOK) })

	codes := map[int]int{}
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/t", nil)
		req.RemoteAddr = "203.0.113.7:1234" // same IP → same bucket
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		codes[w.Code]++
	}
	if codes[http.StatusOK] != 3 {
		t.Errorf("expected 3 allowed, got %d (codes: %v)", codes[http.StatusOK], codes)
	}
	if codes[http.StatusTooManyRequests] != 3 {
		t.Errorf("expected 3 rate-limited, got %d (codes: %v)", codes[http.StatusTooManyRequests], codes)
	}
}
