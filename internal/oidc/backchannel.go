package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
)

const (
	backchannelEventURI  = "http://schemas.openid.net/event/backchannel-logout"
	maxLogoutBodyBytes   = 64 << 10
	maxRevokedEntries    = 10000
	maxLogoutTokenMaxAge = 5 * time.Minute
)

type logoutClaims struct {
	jwt.RegisteredClaims
	SID    string                     `json:"sid"`
	Nonce  string                     `json:"nonce"`
	Events map[string]json.RawMessage `json:"events"`
}

// handleBackchannelLogout implements OpenID Connect Back-Channel Logout 1.0
// (POST /oauth2/backchannel-logout with form field logout_token).
func (m *Manager) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBodyBytes)
	if err := r.ParseForm(); err != nil {
		m.record("backchannel_logout_error")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	rawToken := strings.TrimSpace(r.PostForm.Get("logout_token"))
	if rawToken == "" {
		m.record("backchannel_logout_error")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	sid, sub, err := m.verifyLogoutToken(r.Context(), rawToken)
	if err != nil {
		m.record("backchannel_logout_error")
		m.logger.Warn("rejected invalid backchannel logout token")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	m.revoke(sid, sub)
	m.record("backchannel_logout")
	w.WriteHeader(http.StatusOK)
}

func (m *Manager) verifyLogoutToken(ctx context.Context, raw string) (sid, sub string, err error) {
	if m.keys == nil || m.logoutParser == nil {
		return "", "", errors.New("backchannel logout is not configured")
	}
	if len(raw) == 0 || len(raw) > 65536 {
		return "", "", errors.New("invalid logout token length")
	}
	var c logoutClaims
	tok, err := m.logoutParser.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > 256 {
			return nil, errors.New("missing kid")
		}
		for _, forbidden := range [5]string{"crit", "b64", "jku", "x5u", "jwk"} {
			if _, ok := t.Header[forbidden]; ok {
				return nil, errors.New("forbidden header")
			}
		}
		return m.keys.Key(ctx, kid, t.Method.Alg())
	})
	if err != nil || tok == nil || !tok.Valid {
		return "", "", errors.New("invalid logout token signature")
	}
	// Per OIDC Back-Channel Logout 1.0 §2.4:
	// - nonce MUST NOT be present
	// - iat MUST be present and recent
	// - events MUST contain backchannel-logout URI mapping to a JSON object
	// - at least one of sid or sub MUST be present
	if c.Nonce != "" {
		return "", "", errors.New("logout token must not contain nonce")
	}
	if c.IssuedAt == nil || time.Since(c.IssuedAt.Time) > maxLogoutTokenMaxAge {
		return "", "", errors.New("logout token iat missing or too old")
	}
	rawEv, ok := c.Events[backchannelEventURI]
	if !ok {
		return "", "", errors.New("missing backchannel-logout event")
	}
	var evObj map[string]any
	if err := json.Unmarshal(rawEv, &evObj); err != nil {
		return "", "", errors.New("invalid backchannel-logout event payload")
	}
	if c.SID == "" && c.Subject == "" {
		return "", "", errors.New("logout token missing sid and sub")
	}
	return c.SID, c.Subject, nil
}

func (m *Manager) revoke(sid, sub string) {
	now := time.Now()
	exp := now.Add(m.sessionMaxAge)
	m.revokeMu.Lock()
	defer m.revokeMu.Unlock()
	if len(m.revokedSIDs) >= maxRevokedEntries {
		for k, v := range m.revokedSIDs {
			if !now.Before(v) {
				delete(m.revokedSIDs, k)
			}
		}
		if len(m.revokedSIDs) >= maxRevokedEntries {
			for k := range m.revokedSIDs {
				delete(m.revokedSIDs, k)
				break
			}
		}
	}
	if len(m.revokedSubs) >= maxRevokedEntries {
		cutoff := now.Add(-m.sessionMaxAge)
		for k, v := range m.revokedSubs {
			if v.Before(cutoff) {
				delete(m.revokedSubs, k)
			}
		}
		if len(m.revokedSubs) >= maxRevokedEntries {
			for k := range m.revokedSubs {
				delete(m.revokedSubs, k)
				break
			}
		}
	}
	if sid != "" {
		m.revokedSIDs[sid] = exp
	} else if sub != "" {
		// Only record subject-wide revocation when sid is absent, so logging out
		// a single browser session does not terminate unrelated sessions.
		m.revokedSubs[sub] = now
	}
}

func (m *Manager) isRevoked(sid, sub string, issuedAt int64) bool {
	if sid == "" && sub == "" {
		return false
	}
	now := time.Now()
	m.revokeMu.RLock()
	defer m.revokeMu.RUnlock()
	if sid != "" {
		if exp, ok := m.revokedSIDs[sid]; ok && now.Before(exp) {
			return true
		}
	}
	if sub != "" {
		if revokedAt, ok := m.revokedSubs[sub]; ok && now.Sub(revokedAt) <= m.sessionMaxAge {
			// Only invalidate sessions created at or before the revocation event
			// so a subsequent re-login succeeds immediately.
			if issuedAt == 0 || issuedAt <= revokedAt.Unix() {
				return true
			}
		}
	}
	return false
}

func normalizeAllowedDomains(domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, " \t\r\n/\\:@?*") || d == "." {
			return nil, errors.New("invalid OIDC_ALLOWED_REDIRECT_DOMAINS entry")
		}
		out = append(out, d)
	}
	return out, nil
}

func (m *Manager) isAllowedRedirectHost(host string) bool {
	if len(m.allowedRedirectDomains) == 0 || host == "" {
		return false
	}
	h := host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		h = parsedHost
	}
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return false
	}
	for _, allowed := range m.allowedRedirectDomains {
		if strings.HasPrefix(allowed, ".") {
			if strings.HasSuffix(h, allowed) && len(h) > len(allowed) {
				return true
			}
		} else if h == allowed {
			return true
		}
	}
	return false
}

func (m *Manager) safeRedirectURL(rd string) string {
	if rd == "" {
		return "/"
	}
	for _, r := range rd {
		if unicode.IsControl(r) {
			return "/"
		}
	}
	if strings.HasPrefix(rd, "/") {
		return safeRedirectPath(rd)
	}
	if len(m.allowedRedirectDomains) == 0 {
		return "/"
	}
	u, err := url.Parse(rd)
	if err != nil || u == nil || u.User != nil || u.Host == "" {
		return "/"
	}
	if u.Scheme != "https" && (u.Scheme != "http" || m.cookieSecure) {
		return "/"
	}
	if !m.isAllowedRedirectHost(u.Host) {
		return "/"
	}
	return u.String()
}

func (m *Manager) redirectTargetForRequest(r *http.Request) string {
	reqURI := safeRedirectPath(r.URL.RequestURI())
	if len(m.allowedRedirectDomains) == 0 {
		return reqURI
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if !m.isAllowedRedirectHost(host) {
		return reqURI
	}
	scheme := "https"
	if !m.cookieSecure && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "http") {
		scheme = "http"
	}
	return m.safeRedirectURL(scheme + "://" + host + reqURI)
}
