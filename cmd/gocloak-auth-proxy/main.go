package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/acl"
	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
	"github.com/Nerzal/gocloak-auth-proxy/internal/config"
	"github.com/Nerzal/gocloak-auth-proxy/internal/health"
	"github.com/Nerzal/gocloak-auth-proxy/internal/jwks"
	"github.com/Nerzal/gocloak-auth-proxy/internal/keycloak"
	"github.com/Nerzal/gocloak-auth-proxy/internal/logging"
	"github.com/Nerzal/gocloak-auth-proxy/internal/metrics"
	"github.com/Nerzal/gocloak-auth-proxy/internal/oidc"
	"github.com/Nerzal/gocloak-auth-proxy/internal/proxy"
	"github.com/Nerzal/gocloak-auth-proxy/internal/tlsutil"
)

func main() {
	if err := run(); err != nil {
		logging.New(os.Stderr).Error("server stopped", "reason", err.Error())
		os.Exit(1)
	}
}

func buildHandler(cfg config.Config, logger *slog.Logger, reg *metrics.Registry) (http.Handler, *jwks.Cache, error) {
	kcTLS, err := tlsutil.ClientConfig(cfg.KeycloakCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid KEYCLOAK_CA_FILE: %w", err)
	}
	upstreamTLS, err := tlsutil.ClientConfig(cfg.UpstreamCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid UPSTREAM_CA_FILE: %w", err)
	}
	cache, err := jwks.NewWithOptions(cfg.Issuer, cfg.JWKSRefreshInterval, jwks.Options{
		Logger:    logger,
		TLSConfig: kcTLS,
		OnRefresh: func(ok bool) {
			reg.RecordJWKSRefresh(ok)
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("invalid JWKS configuration: %w", err)
	}

	var introspector auth.TokenIntrospector
	if cfg.IntrospectionEnabled {
		intro, err := keycloak.NewIntrospector(cfg.Issuer, cfg.ClientID, cfg.ClientSecret, cfg.IntrospectionCacheTTL, kcTLS, reg.RecordIntrospection)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid introspection configuration: %w", err)
		}
		introspector = intro
	}

	verifier, err := auth.NewWithOptions(cache, auth.Options{
		Issuer:               cfg.Issuer,
		Audience:             cfg.Audience,
		ClockSkew:            cfg.ClockSkew,
		AllowedAlgorithms:    cfg.AllowedAlgorithms,
		RequiredRealmRoles:   cfg.RequiredRealmRoles,
		RequiredClientRoles:  cfg.RequiredClientRoles,
		ClientID:             cfg.ClientID,
		RequireAnyRole:       cfg.RequireAnyRole,
		RequiredGroups:       cfg.RequiredGroups,
		RequireAnyGroup:      cfg.RequireAnyGroup,
		RequiredScopes:       cfg.RequiredScopes,
		RequiredACR:          cfg.RequiredACR,
		RequireEmailVerified: cfg.RequireEmailVerified,
		RequiredAZP:          cfg.RequiredAZP,
		RequiredOrganization: cfg.RequiredOrganization,
		CustomClaimHeaders:   cfg.CustomClaimHeaders,
		Introspector:         introspector,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("invalid authentication configuration: %w", err)
	}

	var policy *acl.Policy
	if len(cfg.PublicPaths) > 0 || len(cfg.OptionalAuthPaths) > 0 || cfg.AllowCORSPreflight || len(cfg.RouteRules) > 0 {
		policy, err = acl.New(cfg.PublicPaths, cfg.OptionalAuthPaths, cfg.AllowCORSPreflight, cfg.RouteRules)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid ACL configuration: %w", err)
		}
	}

	var uma proxy.Authorizer
	if cfg.UMAEnabled {
		umaAud := cfg.ClientID
		if umaAud == "" {
			umaAud = cfg.Audience
		}
		umaAuth, err := keycloak.NewUMAAuthorizer(cfg.Issuer, umaAud, cfg.UMAMethodScope, kcTLS, reg.RecordUMA)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid UMA configuration: %w", err)
		}
		uma = umaAuth
	}

	var oidcMgr *oidc.Manager
	if cfg.OIDCEnabled {
		oidcMgr, err = oidc.New(oidc.Config{
			Issuer:                  cfg.Issuer,
			ClientID:                cfg.ClientID,
			ClientSecret:            cfg.ClientSecret,
			RedirectURL:             cfg.OIDCRedirectURL,
			PostLogoutURL:           cfg.OIDCPostLogoutURL,
			CookieSecret:            cfg.OIDCCookieSecret,
			CookieName:              cfg.OIDCCookieName,
			CookieSecure:            cfg.OIDCCookieSecure,
			CookieSameSite:          cfg.OIDCCookieSameSite,
			Scopes:                  cfg.OIDCScopes,
			SessionMaxAge:           cfg.OIDCSessionMaxAge,
			RedirectUnauthenticated: cfg.OIDCRedirectUnauth,
			TLSConfig:               kcTLS,
			Logger:                  logger,
			OnEvent:                 reg.RecordOIDC,
		}, verifier)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid OIDC configuration: %w", err)
		}
	}

	extraHeaders := make([]string, 0, len(cfg.CustomClaimHeaders))
	for h := range cfg.CustomClaimHeaders {
		extraHeaders = append(extraHeaders, h)
	}
	proxyOpts := proxy.Options{
		Headers: proxy.HeaderNames{
			User:   cfg.HeaderUser,
			Email:  cfg.HeaderEmail,
			Groups: cfg.HeaderGroups,
			Roles:  cfg.HeaderRoles,
		},
		ExtraHeaders:           extraHeaders,
		PassAccessToken:        cfg.PassAccessToken,
		ACL:                    policy,
		UMA:                    uma,
		Session:                oidcMgr,
		TLSConfig:              upstreamTLS,
		UpstreamHeaderTimeout:  cfg.UpstreamHeaderTimeout,
		UpstreamRequestTimeout: cfg.UpstreamRequestTimeout,
		DisableRequestTimeout:  cfg.DisableUpstreamTimeout,
		Logger:                 logger,
		Metrics:                reg,
	}
	var handler http.Handler
	if cfg.UpstreamURL == "" {
		handler, err = proxy.NewForwardAuthWithOptions(verifier, proxyOpts)
	} else {
		handler, err = proxy.NewReverseProxyWithOptions(verifier, cfg.UpstreamURL, proxyOpts)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("invalid proxy configuration: %w", err)
	}

	mux := http.NewServeMux()
	operational := health.New(cache)
	mux.Handle("/healthz", operational)
	mux.Handle("/readyz", operational)
	if oidcMgr != nil {
		oidcMgr.RegisterRoutes(mux)
	}
	if cfg.UpstreamURL == "" {
		mux.Handle("/auth", handler)
	} else {
		mux.Handle("/", handler)
	}
	return mux, cache, nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	logger, err := logging.NewWithLevel(os.Stderr, cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	reg := metrics.New()
	mux, cache, err := buildHandler(cfg, logger, reg)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: cfg.ServerReadHeaderTimeout,
		ReadTimeout:       cfg.ServerReadTimeout,
		WriteTimeout:      cfg.ServerWriteTimeout,
		IdleTimeout:       cfg.ServerIdleTimeout,
		MaxHeaderBytes:    32 << 10,
	}
	if cfg.TLSCertFile != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", cfg.ListenAddr, err)
	}
	defer func() { _ = listener.Close() }()

	var metricsServer *http.Server
	var metricsListener net.Listener
	if cfg.MetricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", reg.Handler())
		metricsServer = &http.Server{
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		metricsListener, err = net.Listen("tcp", cfg.MetricsAddr)
		if err != nil {
			return fmt.Errorf("cannot listen on metrics address %s: %w", cfg.MetricsAddr, err)
		}
		defer func() { _ = metricsListener.Close() }()
	}

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
	metricsDone := make(chan struct{})
	if metricsServer != nil {
		go func() {
			defer close(metricsDone)
			logger.Info("metrics server starting", "addr", cfg.MetricsAddr)
			if err := metricsServer.Serve(metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics server failed", "reason", err.Error())
			}
		}()
	} else {
		close(metricsDone)
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
		if metricsServer != nil {
			if err := metricsServer.Shutdown(shutdown); err != nil {
				_ = metricsServer.Close()
			}
		}
	}()
	logger.Info("server starting", "addr", cfg.ListenAddr, "tls", cfg.TLSCertFile != "")
	if cfg.TLSCertFile != "" {
		err = server.ServeTLS(listener, cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		err = server.Serve(listener)
	}
	stop()
	<-shutdownDone
	<-cacheDone
	<-metricsDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server failed: %w", err)
	}
	return nil
}
