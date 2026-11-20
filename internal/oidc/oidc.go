// Package oidc implements Browser SSO for Keycloak using Authorization Code
// Flow with PKCE, AES-256-GCM encrypted chunked cookies, automatic token
// refresh, and RP-initiated logout.
package oidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
	"github.com/Nerzal/gocloak-auth-proxy/internal/keycloak"
	"github.com/Nerzal/gocloak/v14"
)

const (
	defaultCookieName    = "__Host-gocloak_session"
	stateCookieSuffix    = "_state"
	maxCookieChunkSize   = 3500
	maxCookieChunks      = 8
	maxTokenRespBytes    = 1 << 20
	tokenHTTPTimeout     = 5 * time.Second
	stateCookieTTL       = 5 * time.Minute
	refreshEarlyMargin   = 30 * time.Second
	refreshCacheTTL      = 5 * time.Second
	maxRefreshCacheItems = 4096
	defaultSessionMax    = 24 * time.Hour
)

var (
	aadSession = []byte("session")
	aadState   = []byte("state")
)

// TokenVerifier verifies a bearer authorization header value.
type TokenVerifier interface {
	Verify(ctx context.Context, authorization string) (auth.Identity, error)
}

// Config configures OIDC browser SSO.
type Config struct {
	Issuer                  string
	ClientID                string
	ClientSecret            string
	RedirectURL             string // e.g. https://app.example.com/oauth2/callback
	PostLogoutURL           string // optional; defaults to "/"
	CookieSecret            string // minimum 32 bytes
	CookieName              string // optional; defaults to __Host-gocloak_session (or gocloak_session if !CookieSecure)
	CookieSecure            bool
	CookieSameSite          http.SameSite // defaults to http.SameSiteLaxMode
	Scopes                  []string      // defaults to ["openid", "profile", "email"]
	SessionMaxAge           time.Duration // defaults to 24h
	RedirectUnauthenticated bool
	TLSConfig               *tls.Config
	Logger                  *slog.Logger
	OnEvent                 func(event string)
}

type authState struct {
	State        string `json:"s"`
	Nonce        string `json:"n"`
	CodeVerifier string `json:"v"`
	Redirect     string `json:"r"`
	ExpiresAt    int64  `json:"e"`
}

type sessionData struct {
	AccessToken      string `json:"a"`
	RefreshToken     string `json:"r,omitempty"`
	IDToken          string `json:"i,omitempty"`
	ExpiresAt        int64  `json:"e"`
	SessionExpiresAt int64  `json:"se"`
}

type refreshFlight struct {
	done chan struct{}
	sess sessionData
	err  error
}

type refreshCacheEntry struct {
	sess    sessionData
	expires time.Time
}

// Manager handles OIDC browser login, callback, logout, and session cookie resolution.
type Manager struct {
	issuer         string
	realm          string
	clientID       string
	clientSecret   string
	redirectURL    string
	postLogoutURL  string
	scopes         string
	cookieName     string
	stateCookie    string
	cookieSecure   bool
	sameSite       http.SameSite
	sessionMaxAge  time.Duration
	redirectUnauth bool
	aead           cipher.AEAD
	httpClient     *http.Client
	kcClient       *gocloak.GoCloak
	verifier       TokenVerifier
	logger         *slog.Logger
	onEvent        func(string)

	refreshMu      sync.Mutex
	refreshFlights map[[32]byte]*refreshFlight
	refreshCache   map[[32]byte]refreshCacheEntry
}

// New constructs a validated OIDC browser SSO manager.
func New(cfg Config, verifier TokenVerifier) (*Manager, error) {
	if verifier == nil {
		return nil, errors.New("verifier is required for OIDC")
	}
	baseURL, realm, err := keycloak.ParseIssuer(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("CLIENT_ID is required for OIDC")
	}
	if len(cfg.CookieSecret) < 32 {
		return nil, errors.New("OIDC_COOKIE_SECRET must be at least 32 characters")
	}
	ru, err := url.Parse(cfg.RedirectURL)
	if err != nil || ru == nil || (ru.Scheme != "http" && ru.Scheme != "https") || ru.Host == "" || ru.User != nil || ru.Fragment != "" {
		return nil, errors.New("OIDC_REDIRECT_URL must be an absolute HTTP(S) URL")
	}
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		if cfg.CookieSecure {
			cookieName = defaultCookieName
		} else {
			cookieName = "gocloak_session"
		}
	}
	if strings.HasPrefix(cookieName, "__Host-") && !cfg.CookieSecure {
		return nil, errors.New("__Host- cookie prefix requires OIDC_COOKIE_SECURE=true")
	}
	sameSite := cfg.CookieSameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	if sameSite == http.SameSiteNoneMode && !cfg.CookieSecure {
		return nil, errors.New("SameSite=None requires OIDC_COOKIE_SECURE=true")
	}
	sessionMaxAge := cfg.SessionMaxAge
	if sessionMaxAge <= 0 {
		sessionMaxAge = defaultSessionMax
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	key := sha256.Sum256([]byte(cfg.CookieSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	transport := keycloak.NewBoundedTransport(cfg.TLSConfig, maxTokenRespBytes)
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   tokenHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not allowed on token endpoint")
		},
	}
	kcClient := gocloak.NewClient(baseURL)
	kcClient.RestyClient().SetTransport(transport)
	kcClient.RestyClient().GetClient().CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	postLogout := cfg.PostLogoutURL
	if postLogout == "" {
		postLogout = "/"
	}
	return &Manager{
		issuer:         strings.TrimRight(cfg.Issuer, "/"),
		realm:          realm,
		clientID:       cfg.ClientID,
		clientSecret:   cfg.ClientSecret,
		redirectURL:    cfg.RedirectURL,
		postLogoutURL:  postLogout,
		scopes:         strings.Join(scopes, " "),
		cookieName:     cookieName,
		stateCookie:    cookieName + stateCookieSuffix,
		cookieSecure:   cfg.CookieSecure,
		sameSite:       sameSite,
		sessionMaxAge:  sessionMaxAge,
		redirectUnauth: cfg.RedirectUnauthenticated,
		aead:           aead,
		httpClient:     httpClient,
		kcClient:       kcClient,
		verifier:       verifier,
		logger:         logger,
		onEvent:        cfg.OnEvent,
		refreshFlights: make(map[[32]byte]*refreshFlight),
		refreshCache:   make(map[[32]byte]refreshCacheEntry),
	}, nil
}

// RegisterRoutes mounts /oauth2/start, /oauth2/callback, and /oauth2/logout on mux.
func (m *Manager) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/oauth2/start", m.handleStart)
	mux.HandleFunc("/oauth2/callback", m.handleCallback)
	mux.HandleFunc("/oauth2/logout", m.handleLogout)
}

// StripCookies removes the proxy's own OIDC session and state cookies from
// outbound request headers so they are never leaked to upstream services,
// while preserving unrelated application cookies.
func (m *Manager) StripCookies(headers http.Header) {
	if m == nil {
		return
	}
	rawCookies := headers.Values("Cookie")
	if len(rawCookies) == 0 {
		return
	}
	hasOwn := false
	for _, line := range rawCookies {
		if strings.Contains(line, m.cookieName) {
			hasOwn = true
			break
		}
	}
	if !hasOwn {
		return
	}
	var kept []string
	for _, line := range rawCookies {
		for _, part := range strings.Split(line, ";") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			name, _, _ := strings.Cut(trimmed, "=")
			name = strings.TrimSpace(name)
			if m.isOwnCookie(name) {
				continue
			}
			kept = append(kept, trimmed)
		}
	}
	headers.Del("Cookie")
	if len(kept) > 0 {
		headers.Set("Cookie", strings.Join(kept, "; "))
	}
}

func (m *Manager) isOwnCookie(name string) bool {
	if name == m.cookieName || name == m.stateCookie {
		return true
	}
	if rest, ok := strings.CutPrefix(name, m.cookieName+"_"); ok {
		if idx, err := strconv.Atoi(rest); err == nil && idx >= 1 && idx < maxCookieChunks {
			return true
		}
	}
	return false
}

// ShouldRedirect reports whether an unauthenticated request should be redirected
// to the OIDC login flow rather than receiving 401 Unauthorized.
func (m *Manager) ShouldRedirect(r *http.Request) bool {
	if m == nil || !m.redirectUnauth || r.Method != http.MethodGet {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// RedirectToLogin sends a 302 Found redirect to /oauth2/start with a safe rd target.
func (m *Manager) RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	rd := safeRedirectPath(r.URL.RequestURI())
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/oauth2/start?rd="+url.QueryEscape(rd), http.StatusFound)
}

// ResolveBearer extracts an access token from the encrypted session cookie,
// refreshing it automatically via Keycloak if near expiry with singleflight
// coalescing to stay compatible with refresh token rotation.
func (m *Manager) ResolveBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	if m == nil {
		return "", false
	}
	sess, ok := m.readSession(r)
	if !ok || sess.AccessToken == "" {
		return "", false
	}
	if sess.ExpiresAt > 0 && time.Now().Add(refreshEarlyMargin).Unix() >= sess.ExpiresAt && sess.RefreshToken != "" {
		refreshed, err := m.coalescedRefresh(r.Context(), sess)
		if err != nil {
			m.record("error")
			m.clearSessionCookies(w)
			return "", false
		}
		if err := m.writeSession(w, refreshed); err != nil {
			m.logger.Warn("failed to persist refreshed session cookie")
		} else {
			m.record("refreshed")
		}
		return "Bearer " + refreshed.AccessToken, true
	}
	return "Bearer " + sess.AccessToken, true
}

func (m *Manager) coalescedRefresh(ctx context.Context, prev sessionData) (sessionData, error) {
	key := sha256.Sum256([]byte(prev.RefreshToken))
	m.refreshMu.Lock()
	if cached, ok := m.refreshCache[key]; ok && time.Now().Before(cached.expires) {
		m.refreshMu.Unlock()
		return cached.sess, nil
	}
	if fl, ok := m.refreshFlights[key]; ok {
		m.refreshMu.Unlock()
		select {
		case <-ctx.Done():
			return sessionData{}, errors.New("token refresh canceled")
		case <-fl.done:
			return fl.sess, fl.err
		}
	}
	fl := &refreshFlight{done: make(chan struct{})}
	m.refreshFlights[key] = fl
	m.refreshMu.Unlock()

	fetchCtx := context.WithoutCancel(ctx)
	go func() {
		sess, err := m.refresh(fetchCtx, prev)
		m.refreshMu.Lock()
		fl.sess = sess
		fl.err = err
		delete(m.refreshFlights, key)
		if err == nil {
			if len(m.refreshCache) >= maxRefreshCacheItems {
				now := time.Now()
				for k, v := range m.refreshCache {
					if !now.Before(v.expires) {
						delete(m.refreshCache, k)
					}
				}
				if len(m.refreshCache) >= maxRefreshCacheItems {
					m.refreshCache = make(map[[32]byte]refreshCacheEntry)
				}
			}
			m.refreshCache[key] = refreshCacheEntry{sess: sess, expires: time.Now().Add(refreshCacheTTL)}
		}
		close(fl.done)
		m.refreshMu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return sessionData{}, errors.New("token refresh canceled")
	case <-fl.done:
		return fl.sess, fl.err
	}
}

func (m *Manager) handleStart(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	verifier, err := randomToken(32)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	rd := safeRedirectPath(r.URL.Query().Get("rd"))

	st := authState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		Redirect:     rd,
		ExpiresAt:    time.Now().Add(stateCookieTTL).Unix(),
	}
	encoded, err := m.sealJSON(st, aadState)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, m.newCookie(m.stateCookie, encoded, int(stateCookieTTL.Seconds())))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.clientID},
		"redirect_uri":          {m.redirectURL},
		"scope":                 {m.scopes},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	m.record("started")
	http.Redirect(w, r, m.issuer+"/protocol/openid-connect/auth?"+q.Encode(), http.StatusFound)
}

func (m *Manager) handleCallback(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie(m.stateCookie)
	m.clearCookie(w, m.stateCookie)
	if err != nil || c.Value == "" {
		m.record("error")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var st authState
	if err := m.openJSON(c.Value, aadState, &st); err != nil || time.Now().Unix() > st.ExpiresAt {
		m.record("error")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	gotState := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if code == "" || len(gotState) == 0 || subtle.ConstantTimeCompare([]byte(gotState), []byte(st.State)) != 1 {
		m.record("error")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sess, err := m.exchangeCode(r.Context(), code, st.CodeVerifier)
	if err != nil {
		m.record("error")
		m.logger.Warn("OIDC code exchange failed")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if sess.IDToken != "" && !m.verifyIDToken(sess.IDToken, st.Nonce) {
		m.record("error")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if _, err := m.verifier.Verify(r.Context(), "Bearer "+sess.AccessToken); err != nil {
		m.record("error")
		if errors.Is(err, auth.ErrForbidden) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err := m.writeSession(w, sess); err != nil {
		m.record("error")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	m.record("success")
	http.Redirect(w, r, safeRedirectPath(st.Redirect), http.StatusFound)
}

func (m *Manager) verifyIDToken(idToken, expectedNonce string) bool {
	if expectedNonce == "" {
		return false
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
		Exp      int64           `json:"exp"`
		Nonce    string          `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Nonce == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return false
	}
	if claims.Issuer != m.issuer || claims.Exp <= time.Now().Unix() {
		return false
	}
	if !audienceContains(claims.Audience, m.clientID) {
		return false
	}
	return true
}

func audienceContains(raw json.RawMessage, target string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if raw[0] == '"' && json.Unmarshal(raw, &single) == nil {
		return single == target
	}
	var list []string
	if raw[0] == '[' && json.Unmarshal(raw, &list) == nil {
		for _, item := range list {
			if item == target {
				return true
			}
		}
	}
	return false
}

func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// Mitigate cross-site logout CSRF on browser requests.
	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}
	sess, hasSession := m.readSession(r)
	m.clearSessionCookies(w)
	m.clearCookie(w, m.stateCookie)
	if hasSession && sess.RefreshToken != "" && m.clientSecret != "" {
		ctx, cancel := context.WithTimeout(r.Context(), tokenHTTPTimeout)
		defer cancel()
		_ = m.kcClient.Logout(ctx, m.clientID, m.clientSecret, m.realm, sess.RefreshToken)
	}
	m.record("logout")
	target := m.postLogoutURL
	if hasSession && sess.IDToken != "" && (strings.HasPrefix(m.postLogoutURL, "http://") || strings.HasPrefix(m.postLogoutURL, "https://")) {
		q := url.Values{
			"id_token_hint":            {sess.IDToken},
			"post_logout_redirect_uri": {m.postLogoutURL},
		}
		target = m.issuer + "/protocol/openid-connect/logout?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (m *Manager) exchangeCode(ctx context.Context, code, codeVerifier string) (sessionData, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {m.clientID},
		"code":          {code},
		"redirect_uri":  {m.redirectURL},
		"code_verifier": {codeVerifier},
	}
	if m.clientSecret != "" {
		form.Set("client_secret", m.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return sessionData{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return sessionData{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return sessionData{}, fmt.Errorf("token endpoint status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenRespBytes+1))
	if err != nil || len(body) > maxTokenRespBytes {
		return sessionData{}, errors.New("invalid token response size")
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return sessionData{}, errors.New("invalid token response")
	}
	var exp int64
	if tok.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()
	}
	return sessionData{
		AccessToken:      tok.AccessToken,
		RefreshToken:     tok.RefreshToken,
		IDToken:          tok.IDToken,
		ExpiresAt:        exp,
		SessionExpiresAt: time.Now().Add(m.sessionMaxAge).Unix(),
	}, nil
}

func (m *Manager) refresh(ctx context.Context, prev sessionData) (sessionData, error) {
	reqCtx, cancel := context.WithTimeout(ctx, tokenHTTPTimeout)
	defer cancel()
	jwtResp, err := m.kcClient.RefreshToken(reqCtx, prev.RefreshToken, m.clientID, m.clientSecret, m.realm)
	if err != nil || jwtResp == nil || jwtResp.AccessToken == "" {
		return sessionData{}, errors.New("token refresh failed")
	}
	refreshTok := jwtResp.RefreshToken
	if refreshTok == "" {
		refreshTok = prev.RefreshToken
	}
	idTok := jwtResp.IDToken
	if idTok == "" {
		idTok = prev.IDToken
	}
	var exp int64
	if jwtResp.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(jwtResp.ExpiresIn) * time.Second).Unix()
	}
	return sessionData{
		AccessToken:      jwtResp.AccessToken,
		RefreshToken:     refreshTok,
		IDToken:          idTok,
		ExpiresAt:        exp,
		SessionExpiresAt: prev.SessionExpiresAt,
	}, nil
}

func (m *Manager) writeSession(w http.ResponseWriter, sess sessionData) error {
	encoded, err := m.sealJSON(sess, aadSession)
	if err != nil {
		return err
	}
	chunks := splitChunks(encoded, maxCookieChunkSize)
	if len(chunks) > maxCookieChunks {
		return errors.New("session cookie exceeds maximum chunk limit")
	}
	for i, chunk := range chunks {
		http.SetCookie(w, m.newCookie(m.chunkName(i), chunk, int(m.sessionMaxAge.Seconds())))
	}
	// Clear only the next sentinel chunk so readSession stops at len(chunks)
	// without emitting 7 redundant Set-Cookie headers on every login/refresh.
	if len(chunks) < maxCookieChunks {
		m.clearCookie(w, m.chunkName(len(chunks)))
	}
	return nil
}

func (m *Manager) readSession(r *http.Request) (sessionData, bool) {
	c0, err := r.Cookie(m.cookieName)
	if err != nil || c0.Value == "" {
		return sessionData{}, false
	}
	encoded := c0.Value
	if len(c0.Value) == maxCookieChunkSize {
		var b strings.Builder
		b.Grow(maxCookieChunkSize * 2)
		b.WriteString(c0.Value)
		for i := 1; i < maxCookieChunks; i++ {
			c, err := r.Cookie(m.chunkName(i))
			if err != nil || c.Value == "" {
				break
			}
			b.WriteString(c.Value)
			if len(c.Value) < maxCookieChunkSize {
				break
			}
		}
		encoded = b.String()
	}
	var sess sessionData
	if err := m.openJSON(encoded, aadSession, &sess); err != nil {
		return sessionData{}, false
	}
	if sess.SessionExpiresAt > 0 && time.Now().Unix() > sess.SessionExpiresAt {
		return sessionData{}, false
	}
	return sess, true
}

func (m *Manager) clearSessionCookies(w http.ResponseWriter) {
	for i := 0; i < maxCookieChunks; i++ {
		m.clearCookie(w, m.chunkName(i))
	}
}

func (m *Manager) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, m.newCookie(name, "", -1))
}

func (m *Manager) newCookie(name, value string, maxAge int) *http.Cookie {
	// #nosec G124 -- HttpOnly is always true, Secure defaults to true, and SameSite defaults to Lax; configurable only for local HTTP development.
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	c.Secure = m.cookieSecure
	c.SameSite = m.sameSite
	return c
}

func (m *Manager) chunkName(index int) string {
	if index == 0 {
		return m.cookieName
	}
	return m.cookieName + "_" + strconv.Itoa(index)
}

func (m *Manager) sealJSON(v any, aad []byte) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := m.aead.Seal(nonce, nonce, plain, aad)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (m *Manager) openJSON(encoded string, aad []byte, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) < m.aead.NonceSize() {
		return errors.New("invalid encrypted cookie")
	}
	nonce := raw[:m.aead.NonceSize()]
	ciphertext := raw[m.aead.NonceSize():]
	plain, err := m.aead.Open(ciphertext[:0], nonce, ciphertext, aad)
	if err != nil {
		return errors.New("cookie authentication failed")
	}
	return json.Unmarshal(plain, dst)
}

func splitChunks(s string, size int) []string {
	if len(s) <= size {
		return []string{s}
	}
	var chunks []string
	for len(s) > size {
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func safeRedirectPath(rd string) string {
	if rd == "" || !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") {
		return "/"
	}
	for _, r := range rd {
		if unicode.IsControl(r) {
			return "/"
		}
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return rd
}

func setNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (m *Manager) record(event string) {
	if m.onEvent != nil {
		m.onEvent(event)
	}
}
