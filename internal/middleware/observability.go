package middleware

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel/trace"
)

const (
	// RequestIDKey is the gin context key holding the correlation id.
	RequestIDKey = "request_id"
	// HeaderRequestID is the inbound/outbound correlation header.
	HeaderRequestID = "X-Request-Id"
)

var httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "http_request_duration_seconds",
	Help:    "Gateway HTTP request duration in seconds.",
	Buckets: prometheus.DefBuckets,
}, []string{"method", "route", "status"})

// RequestID assigns a correlation id (reusing an inbound X-Request-Id if
// present), stores it for downstream propagation, and echoes it in the response.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(HeaderRequestID)
		if id == "" {
			id = uuid.NewString()
		}
		c.Set(RequestIDKey, id)
		c.Writer.Header().Set(HeaderRequestID, id)
		c.Next()
	}
}

// Observability records a Prometheus latency histogram and a structured access
// log per request, correlated by request id and trace id.
func Observability(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		dur := time.Since(start)
		httpDuration.WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).Observe(dur.Seconds())
		traceID := ""
		if sc := trace.SpanContextFromContext(c.Request.Context()); sc.HasTraceID() {
			traceID = sc.TraceID().String()
		}
		log.Info("http.request",
			"method", c.Request.Method,
			"route", route,
			"status", c.Writer.Status(),
			"ms", dur.Milliseconds(),
			"request_id", c.GetString(RequestIDKey),
			"trace_id", traceID,
		)
	}
}
