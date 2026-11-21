package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
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

// Build metadata injected at link time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type cliAction int

const (
	cliRun cliAction = iota
	cliExitOK
	cliCheckConfig
	cliPrintConfig
)

func formatVersion() string {
	return fmt.Sprintf("gocloak-auth-proxy %s (commit %s, built %s)", version, commit, date)
}

func parseCLIAction(args []string, out io.Writer) (cliAction, error) {
	fs := flag.NewFlagSet("gocloak-auth-proxy", flag.ContinueOnError)
	fs.SetOutput(out)
	showVersion := fs.Bool("version", false, "print version information and exit")
	checkConfig := fs.Bool("check-config", false, "validate configuration and referenced files, then exit")
	printConfig := fs.Bool("print-config", false, "print effective configuration with secrets redacted and exit")
	if err := fs.Parse(args); err != nil {
		return cliRun, err
	}
	if *showVersion {
		_, err := fmt.Fprintln(out, formatVersion())
		return cliExitOK, err
	}
	if *checkConfig {
		return cliCheckConfig, nil
	}
	if *printConfig {
		return cliPrintConfig, nil
	}
	return cliRun, nil
}

func parseCLIArgs(args []string, out io.Writer) (bool, error) {
	act, err := parseCLIAction(args, out)
	return act == cliExitOK, err
}

func main() {
	act, err := parseCLIAction(os.Args[1:], os.Stdout)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	switch act {
	case cliExitOK:
		os.Exit(0)
	case cliCheckConfig:
		if err := runCheckConfig(os.Stdout); err != nil {
			logging.New(os.Stderr).Error("configuration check failed", "reason", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	case cliPrintConfig:
		if err := runPrintConfig(os.Stdout); err != nil {
			logging.New(os.Stderr).Error("cannot load configuration", "reason", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	if err := run(); err != nil {
		logging.New(os.Stderr).Error("server stopped", "reason", err.Error())
		os.Exit(1)
	}
}

func runCheckConfig(out io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if cfg.TLSCertFile != "" {
		if _, _, err := tlsutil.ServerConfig(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			return fmt.Errorf("invalid server TLS configuration: %w", err)
		}
	}
	if _, err := buildRuntime(cfg, slog.New(slog.DiscardHandler), metrics.New()); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "configuration valid")
	return err
}

func runPrintConfig(out io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	data, err := cfg.RedactedJSON()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

type proxyRuntime struct {
	handler   http.Handler
	caches    []*jwks.Cache
	drainable *health.Drainable
	closers   []io.Closer
}

// buildHandler constructs the HTTP handler and primary JWKS cache for single-issuer callers and tests.
func buildHandler(cfg config.Config, logger *slog.Logger, reg *metrics.Registry) (http.Handler, *jwks.Cache, error) {
	rt, err := buildRuntime(cfg, logger, reg)
	if err != nil {
		return nil, nil, err
	}
	return rt.handler, rt.caches[0], nil
}

func buildRuntime(cfg config.Config, logger *slog.Logger, reg *metrics.Registry) (*proxyRuntime, error) {
	kcTLS, err := tlsutil.ClientConfigWithCert(cfg.KeycloakCAFile, cfg.KeycloakClientCertFile, cfg.KeycloakClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("invalid Keycloak TLS configuration: %w", err)
	}
	upstreamTLS, err := tlsutil.ClientConfigWithCert(cfg.UpstreamCAFile, cfg.UpstreamClientCertFile, cfg.UpstreamClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream TLS configuration: %w", err)
	}

	issuers := cfg.EffectiveIssuers()
	if len(issuers) == 0 {
		return nil, errors.New("at least one issuer is required")
	}

	caches := make([]*jwks.Cache, 0, len(issuers))
	readinessList := make(health.MultiReadiness, 0, len(issuers))
	verifiers := make(map[string]*auth.Verifier, len(issuers))

	var introspector auth.TokenIntrospector
	if cfg.IntrospectionEnabled {
		intro, err := keycloak.NewIntrospector(cfg.Issuer, cfg.ClientID, cfg.ClientSecret, cfg.IntrospectionCacheTTL, kcTLS, reg.RecordIntrospection)
		if err != nil {
			return nil, fmt.Errorf("invalid introspection configuration: %w", err)
		}
		introspector = intro
	}

	for _, iss := range issuers {
		cache, err := jwks.NewWithOptions(iss, cfg.JWKSRefreshInterval, jwks.Options{
			Logger:    logger,
			TLSConfig: kcTLS,
			OnRefresh: func(ok bool) {
				reg.RecordJWKSRefresh(ok)
			},
		})
		if err != nil {
			return nil, fmt.Errorf("invalid JWKS configuration: %w", err)
		}
		v, err := auth.NewWithOptions(cache, auth.Options{
			Issuer:               iss,
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
			RequiredAMR:          cfg.RequiredAMR,
			RequireEmailVerified: cfg.RequireEmailVerified,
			RequiredAZP:          cfg.RequiredAZP,
			RequiredOrganization: cfg.RequiredOrganization,
			CustomClaimHeaders:   cfg.CustomClaimHeaders,
			Introspector:         introspector,
			TokenCacheSize:       cfg.TokenCacheSize,
		})
		if err != nil {
			return nil, fmt.Errorf("invalid authentication configuration: %w", err)
		}
		caches = append(caches, cache)
		readinessList = append(readinessList, cache)
		verifiers[iss] = v
	}

	var verifier proxy.Verifier
	if len(issuers) == 1 {
		verifier = verifiers[issuers[0]]
	} else {
		mv, err := auth.NewMultiVerifier(verifiers)
		if err != nil {
			return nil, fmt.Errorf("invalid multi-issuer configuration: %w", err)
		}
		verifier = mv
	}

	var policy *acl.Policy
	if len(cfg.PublicPaths) > 0 || len(cfg.OptionalAuthPaths) > 0 || cfg.AllowCORSPreflight || len(cfg.RouteRules) > 0 {
		policy, err = acl.New(cfg.PublicPaths, cfg.OptionalAuthPaths, cfg.AllowCORSPreflight, cfg.RouteRules)
		if err != nil {
			return nil, fmt.Errorf("invalid ACL configuration: %w", err)
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
			return nil, fmt.Errorf("invalid UMA configuration: %w", err)
		}
		uma = umaAuth
	}

	var (
		revStore oidc.RevocationStore
		closers  []io.Closer
	)
	if cfg.RedisAddr != "" {
		var redisTLS *tls.Config
		if cfg.RedisTLS || cfg.RedisCAFile != "" {
			redisTLS, err = tlsutil.ClientConfig(cfg.RedisCAFile)
			if err != nil {
				return nil, fmt.Errorf("invalid Redis TLS configuration: %w", err)
			}
		}
		rs, err := oidc.NewRedisRevocationStore(cfg.RedisAddr, cfg.RedisPassword, redisTLS)
		if err != nil {
			return nil, fmt.Errorf("invalid Redis configuration: %w", err)
		}
		revStore = rs
		closers = append(closers, rs)
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
			CookieSecretPrevious:    cfg.OIDCCookieSecretPrevious,
			CookieName:              cfg.OIDCCookieName,
			CookieDomain:            cfg.OIDCCookieDomain,
			CookieSecure:            cfg.OIDCCookieSecure,
			CookieSameSite:          cfg.OIDCCookieSameSite,
			Scopes:                  cfg.OIDCScopes,
			SessionMaxAge:           cfg.OIDCSessionMaxAge,
			RedirectUnauthenticated: cfg.OIDCRedirectUnauth,
			AllowedRedirectDomains:  cfg.OIDCAllowedRedirectDomains,
			Keys:                    caches[0],
			AllowedAlgorithms:       cfg.AllowedAlgorithms,
			ClockSkew:               cfg.ClockSkew,
			TLSConfig:               kcTLS,
			Logger:                  logger,
			OnEvent:                 reg.RecordOIDC,
			RevocationStore:         revStore,
		}, verifier)
		if err != nil {
			return nil, fmt.Errorf("invalid OIDC configuration: %w", err)
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
		TrustedProxies:         cfg.TrustedProxies,
		AccessLog:              cfg.AccessLog,
	}
	var handler http.Handler
	if cfg.UpstreamURL == "" {
		handler, err = proxy.NewForwardAuthWithOptions(verifier, proxyOpts)
	} else {
		handler, err = proxy.NewReverseProxyWithOptions(verifier, cfg.UpstreamURL, proxyOpts)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid proxy configuration: %w", err)
	}

	drainable := health.NewDrainable(readinessList)
	mux := http.NewServeMux()
	operational := health.New(drainable)
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
	return &proxyRuntime{
		handler:   mux,
		caches:    caches,
		drainable: drainable,
		closers:   closers,
	}, nil
}

func (rt *proxyRuntime) close() {
	for _, c := range rt.closers {
		_ = c.Close()
	}
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
	rt, err := buildRuntime(cfg, logger, reg)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           rt.handler,
		ReadHeaderTimeout: cfg.ServerReadHeaderTimeout,
		ReadTimeout:       cfg.ServerReadTimeout,
		WriteTimeout:      cfg.ServerWriteTimeout,
		IdleTimeout:       cfg.ServerIdleTimeout,
		MaxHeaderBytes:    32 << 10,
	}
	var certReloader *tlsutil.CertReloader
	if cfg.TLSCertFile != "" {
		tlsCfg, reloader, err := tlsutil.ServerConfig(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("invalid server TLS configuration: %w", err)
		}
		server.TLSConfig = tlsCfg
		certReloader = reloader
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

	// SIGHUP reloads TLS certificates on demand without dropping connections.
	if certReloader != nil {
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			defer signal.Stop(sighup)
			for {
				select {
				case <-ctx.Done():
					return
				case <-sighup:
					if err := certReloader.Reload(); err != nil {
						logger.Warn("TLS certificate reload failed")
					} else {
						logger.Info("TLS certificate reloaded")
					}
				}
			}
		}()
	}

	for _, cache := range rt.caches {
		if err := cache.Refresh(ctx); err != nil {
			logger.Warn("initial JWKS refresh failed")
		}
	}
	var cacheWG sync.WaitGroup
	for _, cache := range rt.caches {
		cacheWG.Add(1)
		go func(c *jwks.Cache) {
			defer cacheWG.Done()
			c.Run(ctx)
		}(cache)
	}
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
		rt.drainable.SetDraining(true)
		if cfg.ShutdownDrainDelay > 0 {
			logger.Info("draining connections before shutdown", "delay", cfg.ShutdownDrainDelay.String())
			time.Sleep(cfg.ShutdownDrainDelay)
		}
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
	logger.Info("server starting", "version", version, "addr", cfg.ListenAddr, "tls", cfg.TLSCertFile != "", "issuers", len(rt.caches))
	if cfg.TLSCertFile != "" {
		err = server.ServeTLS(listener, "", "")
	} else {
		err = server.Serve(listener)
	}
	stop()
	<-shutdownDone
	cacheWG.Wait()
	<-metricsDone
	rt.close()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server failed: %w", err)
	}
	return nil
}
