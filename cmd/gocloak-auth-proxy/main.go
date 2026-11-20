package main

import (
	"context"
	"errors"
	"fmt"
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

func buildHandler(cfg config.Config, logger *slog.Logger) (http.Handler, *jwks.Cache, error) {
	cache, err := jwks.New(cfg.Issuer, cfg.JWKSRefreshInterval, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid JWKS configuration: %w", err)
	}
	verifier, err := auth.New(cache, cfg.Issuer, cfg.Audience, cfg.ClockSkew, cfg.RequiredRealmRoles, cfg.RequiredClientRoles, cfg.ClientID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid authentication configuration: %w", err)
	}
	headers := proxy.HeaderNames{
		User:   cfg.HeaderUser,
		Email:  cfg.HeaderEmail,
		Groups: cfg.HeaderGroups,
		Roles:  cfg.HeaderRoles,
	}
	var handler http.Handler
	if cfg.UpstreamURL == "" {
		handler, err = proxy.NewForwardAuth(verifier, headers)
	} else {
		handler, err = proxy.NewReverseProxy(verifier, cfg.UpstreamURL, headers, logger)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("invalid proxy configuration: %w", err)
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
	return mux, cache, nil
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	mux, cache, err := buildHandler(cfg, logger)
	if err != nil {
		return err
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
		return fmt.Errorf("cannot listen on %s: %w", cfg.ListenAddr, err)
	}
	defer func() { _ = listener.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cache.Refresh(ctx); err != nil {
		logger.Warn("initial JWKS refresh failed")
	}
	cacheDone := make(chan struct{})
	go func() {
		defer close(cacheDone)
		cache.Run(ctx)
	}()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	}()
	logger.Info("server starting", "addr", cfg.ListenAddr)
	err = server.Serve(listener)
	stop()
	<-shutdownDone
	<-cacheDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server failed: %w", err)
	}
	return nil
}
