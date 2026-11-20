// Package metrics provides zero-dependency Prometheus/OpenMetrics instrumentation.
package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Registry holds lock-free atomic counters for proxy operations.
type Registry struct {
	forwardAllowed      atomic.Uint64
	forwardUnauthorized atomic.Uint64
	forwardForbidden    atomic.Uint64
	forwardPublic       atomic.Uint64

	reverseAllowed      atomic.Uint64
	reverseUnauthorized atomic.Uint64
	reverseForbidden    atomic.Uint64
	reverseBadGateway   atomic.Uint64
	reversePublic       atomic.Uint64

	jwksSuccess atomic.Uint64
	jwksError   atomic.Uint64
	jwksReady   atomic.Int64

	introspectActive   atomic.Uint64
	introspectInactive atomic.Uint64
	introspectError    atomic.Uint64
	introspectCacheHit atomic.Uint64

	umaAllowed atomic.Uint64
	umaDenied  atomic.Uint64
	umaError   atomic.Uint64

	oidcStarted   atomic.Uint64
	oidcSuccess   atomic.Uint64
	oidcError     atomic.Uint64
	oidcRefreshed atomic.Uint64
	oidcLogout    atomic.Uint64
}

// New creates an initialized metrics registry.
func New() *Registry { return &Registry{} }

func (r *Registry) RecordRequest(mode, result string) {
	if r == nil {
		return
	}
	switch mode {
	case "forward_auth":
		switch result {
		case "allowed":
			r.forwardAllowed.Add(1)
		case "unauthorized":
			r.forwardUnauthorized.Add(1)
		case "forbidden":
			r.forwardForbidden.Add(1)
		case "public":
			r.forwardPublic.Add(1)
		}
	case "reverse_proxy":
		switch result {
		case "allowed":
			r.reverseAllowed.Add(1)
		case "unauthorized":
			r.reverseUnauthorized.Add(1)
		case "forbidden":
			r.reverseForbidden.Add(1)
		case "bad_gateway":
			r.reverseBadGateway.Add(1)
		case "public":
			r.reversePublic.Add(1)
		}
	}
}

func (r *Registry) RecordJWKSRefresh(ok bool) {
	if r == nil {
		return
	}
	if ok {
		r.jwksSuccess.Add(1)
		r.jwksReady.Store(1)
	} else {
		r.jwksError.Add(1)
	}
}

func (r *Registry) SetJWKSReady(ready bool) {
	if r == nil {
		return
	}
	if ready {
		r.jwksReady.Store(1)
	} else {
		r.jwksReady.Store(0)
	}
}

func (r *Registry) RecordIntrospection(result string) {
	if r == nil {
		return
	}
	switch result {
	case "active":
		r.introspectActive.Add(1)
	case "inactive":
		r.introspectInactive.Add(1)
	case "error":
		r.introspectError.Add(1)
	case "cache_hit":
		r.introspectCacheHit.Add(1)
	}
}

func (r *Registry) RecordUMA(result string) {
	if r == nil {
		return
	}
	switch result {
	case "allowed":
		r.umaAllowed.Add(1)
	case "denied":
		r.umaDenied.Add(1)
	case "error":
		r.umaError.Add(1)
	}
}

func (r *Registry) RecordOIDC(result string) {
	if r == nil {
		return
	}
	switch result {
	case "started":
		r.oidcStarted.Add(1)
	case "success":
		r.oidcSuccess.Add(1)
	case "error":
		r.oidcError.Add(1)
	case "refreshed":
		r.oidcRefreshed.Add(1)
	case "logout":
		r.oidcLogout.Add(1)
	}
}

// Handler serves Prometheus text exposition format on GET/HEAD /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if req.Method == http.MethodHead {
			return
		}
		_, _ = fmt.Fprintf(w,
			"# HELP gocloak_auth_proxy_requests_total Total HTTP requests processed by mode and result.\n"+
				"# TYPE gocloak_auth_proxy_requests_total counter\n"+
				"gocloak_auth_proxy_requests_total{mode=\"forward_auth\",result=\"allowed\"} %d\n"+
				"gocloak_auth_proxy_requests_total{mode=\"forward_auth\",result=\"unauthorized\"} %d\n"+
				"gocloak_auth_proxy_requests_total{mode=\"forward_auth\",result=\"forbidden\"} %d\n"+
				"gocloak_auth_proxy_requests_total{mode=\"forward_auth\",result=\"public\"} %d\n"+
				"gocloak_auth_proxy_requests_total{mode=\"reverse_proxy\",result=\"allowed\"} %d\n"+
				"gocloak_auth_proxy_requests_total{mode=\"reverse_proxy\",result=\"unauthorized\"} %d\n"+
				"gocloak_auth_proxy_requests_total{mode=\"reverse_proxy\",result=\"forbidden\"} %d\n"+
				"gocloak_auth_proxy_requests_total{mode=\"reverse_proxy\",result=\"bad_gateway\"} %d\n"+
				"gocloak_auth_proxy_requests_total{mode=\"reverse_proxy\",result=\"public\"} %d\n"+
				"# HELP gocloak_auth_proxy_jwks_refresh_total Total JWKS refresh attempts.\n"+
				"# TYPE gocloak_auth_proxy_jwks_refresh_total counter\n"+
				"gocloak_auth_proxy_jwks_refresh_total{result=\"success\"} %d\n"+
				"gocloak_auth_proxy_jwks_refresh_total{result=\"error\"} %d\n"+
				"# HELP gocloak_auth_proxy_jwks_ready Whether a usable JWKS snapshot is loaded (1=ready, 0=not ready).\n"+
				"# TYPE gocloak_auth_proxy_jwks_ready gauge\n"+
				"gocloak_auth_proxy_jwks_ready %d\n"+
				"# HELP gocloak_auth_proxy_introspection_total Total token introspection evaluations.\n"+
				"# TYPE gocloak_auth_proxy_introspection_total counter\n"+
				"gocloak_auth_proxy_introspection_total{result=\"active\"} %d\n"+
				"gocloak_auth_proxy_introspection_total{result=\"inactive\"} %d\n"+
				"gocloak_auth_proxy_introspection_total{result=\"error\"} %d\n"+
				"gocloak_auth_proxy_introspection_total{result=\"cache_hit\"} %d\n"+
				"# HELP gocloak_auth_proxy_uma_total Total Keycloak UMA authorization evaluations.\n"+
				"# TYPE gocloak_auth_proxy_uma_total counter\n"+
				"gocloak_auth_proxy_uma_total{result=\"allowed\"} %d\n"+
				"gocloak_auth_proxy_uma_total{result=\"denied\"} %d\n"+
				"gocloak_auth_proxy_uma_total{result=\"error\"} %d\n"+
				"# HELP gocloak_auth_proxy_oidc_events_total Total OIDC browser SSO lifecycle events.\n"+
				"# TYPE gocloak_auth_proxy_oidc_events_total counter\n"+
				"gocloak_auth_proxy_oidc_events_total{result=\"started\"} %d\n"+
				"gocloak_auth_proxy_oidc_events_total{result=\"success\"} %d\n"+
				"gocloak_auth_proxy_oidc_events_total{result=\"error\"} %d\n"+
				"gocloak_auth_proxy_oidc_events_total{result=\"refreshed\"} %d\n"+
				"gocloak_auth_proxy_oidc_events_total{result=\"logout\"} %d\n",
			r.forwardAllowed.Load(), r.forwardUnauthorized.Load(), r.forwardForbidden.Load(), r.forwardPublic.Load(),
			r.reverseAllowed.Load(), r.reverseUnauthorized.Load(), r.reverseForbidden.Load(), r.reverseBadGateway.Load(), r.reversePublic.Load(),
			r.jwksSuccess.Load(), r.jwksError.Load(),
			r.jwksReady.Load(),
			r.introspectActive.Load(), r.introspectInactive.Load(), r.introspectError.Load(), r.introspectCacheHit.Load(),
			r.umaAllowed.Load(), r.umaDenied.Load(), r.umaError.Load(),
			r.oidcStarted.Load(), r.oidcSuccess.Load(), r.oidcError.Load(), r.oidcRefreshed.Load(), r.oidcLogout.Load(),
		)
	})
}
