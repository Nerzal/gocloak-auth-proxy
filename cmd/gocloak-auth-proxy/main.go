package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
	"github.com/Nerzal/gocloak-auth-proxy/internal/config"
	"github.com/Nerzal/gocloak-auth-proxy/internal/health"
	"github.com/Nerzal/gocloak-auth-proxy/internal/jwks"
	"github.com/Nerzal/gocloak-auth-proxy/internal/logging"
	"github.com/Nerzal/gocloak-auth-proxy/internal/proxy"
)

func main() {
	logger := logging.New(os.Stderr)
	if err := run(logger); err != nil {
		logger.Error("server stopped", "reason", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return errors.New("invalid configuration")
	}
	cache, err := jwks.New(cfg.Issuer, cfg.JWKSRefreshInterval)
	if err != nil {
		return errors.New("invalid JWKS configuration")
	}
	verifier, err := auth.New(cache, cfg.Issuer, cfg.Audience, cfg.ClockSkew, cfg.RequiredRealmRoles, cfg.RequiredClientRoles, cfg.ClientID)
	if err != nil {
		return errors.New("invalid authentication configuration")
	}
	var handler http.Handler
	if cfg.UpstreamURL == "" {
		handler, err = proxy.NewForwardAuth(verifier, proxy.HeaderNames{})
	} else {
		handler, err = proxy.NewReverseProxy(verifier, cfg.UpstreamURL, proxy.HeaderNames{})
	}
	if err != nil {
		return errors.New("invalid proxy configuration")
	}
	mux := http.NewServeMux()
	operational := health.New(cache)
	mux.Handle("/healthz", operational)
	mux.Handle("/readyz", operational)
	if cfg.UpstreamURL == "" {
		mux.Handle("/auth", handler)
	} else {
		mux.Handle("/", handler)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return errors.New("cannot listen on configured address")
	}
	defer func() { _ = listener.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cache.Refresh(ctx); err != nil {
		logger.Warn("initial JWKS refresh failed")
	}
	go cache.Run(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	}()
	logger.Info("server starting")
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("HTTP server failed")
	}
	return nil
}
