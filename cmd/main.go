package main

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/malvinpratama/iam-go-gateway/internal/client"
	"github.com/malvinpratama/iam-go-gateway/internal/router"
	"github.com/malvinpratama/iam-go-libs/config"
	"github.com/malvinpratama/iam-go-libs/logger"
	"github.com/malvinpratama/iam-go-libs/obs"
)

func main() {
	log := logger.New("gateway")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := config.ValidateSecurity(); err != nil {
		log.Error("insecure configuration", "err", err)
		return
	}
	if config.IsProduction() && config.Getenv("SESSION_SECRET", "") == "" {
		log.Error("SESSION_SECRET must be set in production (signs OIDC browser sessions)")
		return
	}
	if config.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	shutdownTracer, err := obs.InitTracer(ctx, "gateway", config.OTLPEndpoint())
	if err != nil {
		log.Error("init tracer", "err", err)
		return
	}
	defer func() { _ = shutdownTracer(context.Background()) }()

	authAddr := config.Getenv("AUTH_GRPC_ADDR", "localhost:50051")
	userAddr := config.Getenv("USER_GRPC_ADDR", "localhost:50052")
	port := config.Getenv("GATEWAY_HTTP_PORT", "8080")

	clients, err := client.Dial(authAddr, userAddr, config.InternalToken())
	if err != nil {
		log.Error("dial services", "err", err)
		return
	}
	defer clients.Close()

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           router.New(clients, log),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("gateway listening", "port", port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
	}
}
