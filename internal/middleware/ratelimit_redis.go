package middleware

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// NewAuthLimiter returns the per-IP rate-limit middleware: Redis-backed (shared
// across gateway replicas) when REDIS_URL is set, otherwise the in-memory
// fallback (fine for a single instance / local dev).
func NewAuthLimiter(limit int, window time.Duration, log *slog.Logger) gin.HandlerFunc {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return NewRateLimiter(limit, window).Limit()
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		log.Warn("invalid REDIS_URL — using in-memory rate limiter", "err", err)
		return NewRateLimiter(limit, window).Limit()
	}
	log.Info("rate limiter: redis-backed (shared across replicas)")
	// Keep a local in-memory limiter as the fallback for Redis errors, so a Redis
	// outage degrades to per-instance limiting instead of disabling limiting
	// entirely — a brute-force can't ride out a Redis blip.
	return (&redisLimiter{
		rdb:      redis.NewClient(opt),
		limit:    limit,
		window:   window,
		log:      log,
		fallback: NewRateLimiter(limit, window).Limit(),
	}).Limit()
}

// redisLimiter is a per-IP fixed-window limiter whose counters live in Redis, so
// the limit is enforced consistently no matter which replica serves a request.
type redisLimiter struct {
	rdb      *redis.Client
	limit    int
	window   time.Duration
	log      *slog.Logger
	fallback gin.HandlerFunc // in-memory limiter used when Redis errors
}

// atomic INCR + first-write EXPIRE.
var incrExpire = redis.NewScript(
	`local c = redis.call('INCR', KEYS[1]) ` +
		`if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end ` +
		`return c`,
)

func (rl *redisLimiter) Limit() gin.HandlerFunc {
	secs := int64(rl.window / time.Second)
	if secs < 1 {
		secs = 1
	}
	return func(c *gin.Context) {
		if rl.limit <= 0 { // disabled
			c.Next()
			return
		}
		bucket := time.Now().Unix() / secs
		key := "rl:" + c.ClientIP() + ":" + strconv.FormatInt(bucket, 10)
		n, err := incrExpire.Run(c.Request.Context(), rl.rdb, []string{key}, secs).Int64()
		if err != nil {
			// Fail closed-ish: fall back to the local in-memory limiter rather than
			// waving the request through, so a Redis outage can't open a
			// brute-force window.
			rl.log.Warn("rate limiter: redis error, falling back to in-memory limiter", "err", err)
			rl.fallback(c)
			return
		}
		if n > int64(rl.limit) {
			c.Header("Retry-After", strconv.FormatInt(secs, 10))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded, slow down"})
			return
		}
		c.Next()
	}
}
