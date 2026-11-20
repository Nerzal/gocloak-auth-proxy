// Package acl evaluates path- and method-based authentication and role policies.
package acl

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
)

// Mode describes how a matched route should be authenticated.
type Mode int

const (
	ModeRequired Mode = iota
	ModePublic
	ModeOptional
)

// Rule defines method- and path-scoped role requirements.
// Syntax: [METHOD:]/path/pattern=realm:role1,client:role2
type Rule struct {
	Method      string // empty or "*" matches any method
	Pattern     string // exact path or prefix ending in "/*"
	RealmRoles  []string
	ClientRoles []string
}

// Policy evaluates incoming requests against public, optional, and role rules.
type Policy struct {
	publicPaths        []string
	optionalPaths      []string
	allowCORSPreflight bool
	rules              []Rule
}

// New constructs a validated ACL policy.
func New(publicPaths, optionalPaths []string, allowCORSPreflight bool, rawRules []string) (*Policy, error) {
	pub, err := validatePatterns(publicPaths)
	if err != nil {
		return nil, fmt.Errorf("invalid public path: %w", err)
	}
	opt, err := validatePatterns(optionalPaths)
	if err != nil {
		return nil, fmt.Errorf("invalid optional auth path: %w", err)
	}
	rules := make([]Rule, 0, len(rawRules))
	for _, raw := range rawRules {
		r, err := parseRule(raw)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return &Policy{
		publicPaths:        pub,
		optionalPaths:      opt,
		allowCORSPreflight: allowCORSPreflight,
		rules:              rules,
	}, nil
}

func validatePatterns(patterns []string) ([]string, error) {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, " \t\r\n") {
			return nil, fmt.Errorf("invalid pattern %q", p)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseRule(raw string) (Rule, error) {
	raw = strings.TrimSpace(raw)
	lhs, rhs, ok := strings.Cut(raw, "=")
	if !ok || strings.TrimSpace(lhs) == "" || strings.TrimSpace(rhs) == "" {
		return Rule{}, fmt.Errorf("invalid route rule %q", raw)
	}
	lhs = strings.TrimSpace(lhs)
	method := ""
	pattern := lhs
	if !strings.HasPrefix(lhs, "/") {
		m, p, ok := strings.Cut(lhs, ":")
		if !ok || !strings.HasPrefix(p, "/") {
			return Rule{}, fmt.Errorf("invalid route rule target %q", lhs)
		}
		method = strings.ToUpper(strings.TrimSpace(m))
		if method == "*" {
			method = ""
		}
		pattern = strings.TrimSpace(p)
	}
	if strings.Contains(pattern, "..") || strings.ContainsAny(pattern, " \t\r\n") {
		return Rule{}, fmt.Errorf("invalid route rule pattern %q", pattern)
	}
	var realmRoles, clientRoles []string
	for _, entry := range strings.Split(rhs, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return Rule{}, fmt.Errorf("empty role in route rule %q", raw)
		}
		if r, ok := strings.CutPrefix(entry, "realm:"); ok && strings.TrimSpace(r) != "" {
			realmRoles = append(realmRoles, strings.TrimSpace(r))
		} else if c, ok := strings.CutPrefix(entry, "client:"); ok && strings.TrimSpace(c) != "" {
			clientRoles = append(clientRoles, strings.TrimSpace(c))
		} else {
			return Rule{}, fmt.Errorf("role %q must be prefixed with realm: or client:", entry)
		}
	}
	if len(realmRoles) == 0 && len(clientRoles) == 0 {
		return Rule{}, errors.New("route rule requires at least one role")
	}
	return Rule{
		Method:      method,
		Pattern:     pattern,
		RealmRoles:  realmRoles,
		ClientRoles: clientRoles,
	}, nil
}

// NormalizePath cleans a URL path and rejects traversal attempts.
func NormalizePath(rawPath string) (string, bool) {
	if rawPath == "" {
		return "/", true
	}
	if strings.Contains(rawPath, "..") || strings.ContainsAny(rawPath, "\x00\\") {
		return "", false
	}
	cleaned := path.Clean(rawPath)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned, true
}

func matchPattern(pattern, reqPath string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "/*"); ok {
		if prefix == "" {
			return true
		}
		return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
	}
	return reqPath == pattern
}

// AuthMode returns whether the request is public, optional-auth, or requires authentication.
func (p *Policy) AuthMode(r *http.Request) (Mode, bool) {
	if p == nil {
		return ModeRequired, true
	}
	cleanPath, ok := NormalizePath(r.URL.Path)
	if !ok {
		return ModeRequired, false
	}
	if p.allowCORSPreflight && r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != "" {
		return ModePublic, true
	}
	for _, pat := range p.publicPaths {
		if matchPattern(pat, cleanPath) {
			return ModePublic, true
		}
	}
	for _, pat := range p.optionalPaths {
		if matchPattern(pat, cleanPath) {
			return ModeOptional, true
		}
	}
	return ModeRequired, true
}

// Authorize checks route-specific role rules against a verified identity.
func (p *Policy) Authorize(r *http.Request, id auth.Identity) error {
	if p == nil || len(p.rules) == 0 {
		return nil
	}
	cleanPath, ok := NormalizePath(r.URL.Path)
	if !ok {
		return auth.ErrForbidden
	}
	for _, rule := range p.rules {
		if rule.Method != "" && rule.Method != r.Method {
			continue
		}
		if !matchPattern(rule.Pattern, cleanPath) {
			continue
		}
		for _, req := range rule.RealmRoles {
			if !slices.Contains(id.RealmRoles, req) {
				return auth.ErrForbidden
			}
		}
		for _, req := range rule.ClientRoles {
			if !slices.Contains(id.ClientRoles, req) {
				return auth.ErrForbidden
			}
		}
	}
	return nil
}
