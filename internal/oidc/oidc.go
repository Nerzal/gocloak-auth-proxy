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
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
	"github.com/Nerzal/gocloak-auth-proxy/internal/keycloak"
	"github.com/Nerzal/gocloak/v14"
)

const (
	defaultCookieName  = "__Host-gocloak_session"
	stateCookieSuffix  = "_state"
	maxCookieChunkSize = 3500
	maxCookieChunks    = 8
	maxTokenRespBytes  = 1 << 20
	tokenHTTPTimeout   = 5 * time.Second
	stateCookieTTL     = 5 * time.Minute
	refreshEarlyMargin = 30 * time.Second
	defaultSessionMax  = 24 * time.Hour
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
	CodeVerifier string `json:"v"`
	Redirect     string `json:"r"`
	ExpiresAt    int64  `json:"e"`
}

type sessionData struct {
	AccessToken  string `json:"a"`
	RefreshToken string `json:"r,omitempty"`
	IDToken      string `json:"i,omitempty"`
	ExpiresAt    int64  `json:"e"`
}

// Manager handles OIDC browser login, callback, logout, and session cookie resolution.
type Manager struct {
	issuer         string
	baseURL        string
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
	transport      *http.Transport
	verifier       TokenVerifier
	logger         *slog.Logger
	onEvent        func(string)
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
	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: tokenHTTPTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsCfg,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   tokenHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not allowed on token endpoint")
		},
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
		baseURL:        baseURL,
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
		transport:      transport,
		verifier:       verifier,
		logger:         logger,
		onEvent:        cfg.OnEvent,
	}, nil
}

// RegisterRoutes mounts /oauth2/start, /oauth2/callback, and /oauth2/logout on mux.
func (m *Manager) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/oauth2/start", m.handleStart)
	mux.HandleFunc("/oauth2/callback", m.handleCallback)
	mux.HandleFunc("/oauth2/logout", m.handleLogout)
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
// refreshing it automatically via Keycloak if near expiry.
func (m *Manager) ResolveBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	if m == nil {
		return "", false
	}
	sess, ok := m.readSession(r)
	if !ok || sess.AccessToken == "" {
		return "", false
	}
	if sess.ExpiresAt > 0 && time.Now().Add(refreshEarlyMargin).Unix() >= sess.ExpiresAt && sess.RefreshToken != "" {
		refreshed, err := m.refresh(r.Context(), sess)
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
		CodeVerifier: verifier,
		Redirect:     rd,
		ExpiresAt:    time.Now().Add(stateCookieTTL).Unix(),
	}
	encoded, err := m.sealJSON(st, "state")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.stateCookie,
		Value:    encoded,
		Path:     "/",
		MaxAge:   int(stateCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   m.cookieSecure,
		SameSite: m.sameSite,
	})
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.clientID},
		"redirect_uri":          {m.redirectURL},
		"scope":                 {m.scopes},
		"state":                 {state},
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
	if err := m.openJSON(c.Value, "state", &st); err != nil || time.Now().Unix() > st.ExpiresAt {
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

func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, hasSession := m.readSession(r)
	m.clearSessionCookies(w)
	m.clearCookie(w, m.stateCookie)
	if hasSession && sess.RefreshToken != "" && m.clientSecret != "" {
		ctx, cancel := context.WithTimeout(r.Context(), tokenHTTPTimeout)
		defer cancel()
		client := gocloak.NewClient(m.baseURL)
		client.RestyClient().SetTransport(m.transport)
		_ = client.Logout(ctx, m.clientID, m.clientSecret, m.realm, sess.RefreshToken)
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
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		ExpiresAt:    exp,
	}, nil
}

func (m *Manager) refresh(ctx context.Context, prev sessionData) (sessionData, error) {
	reqCtx, cancel := context.WithTimeout(ctx, tokenHTTPTimeout)
	defer cancel()
	client := gocloak.NewClient(m.baseURL)
	client.RestyClient().SetTransport(m.transport)
	client.RestyClient().GetClient().CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	}
	jwtResp, err := client.RefreshToken(reqCtx, prev.RefreshToken, m.clientID, m.clientSecret, m.realm)
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
		AccessToken:  jwtResp.AccessToken,
		RefreshToken: refreshTok,
		IDToken:      idTok,
		ExpiresAt:    exp,
	}, nil
}

func (m *Manager) writeSession(w http.ResponseWriter, sess sessionData) error {
	encoded, err := m.sealJSON(sess, "session")
	if err != nil {
		return err
	}
	chunks := splitChunks(encoded, maxCookieChunkSize)
	if len(chunks) > maxCookieChunks {
		return errors.New("session cookie exceeds maximum chunk limit")
	}
	for i, chunk := range chunks {
		http.SetCookie(w, &http.Cookie{
			Name:     m.chunkName(i),
			Value:    chunk,
			Path:     "/",
			MaxAge:   int(m.sessionMaxAge.Seconds()),
			HttpOnly: true,
			Secure:   m.cookieSecure,
			SameSite: m.sameSite,
		})
	}
	for i := len(chunks); i < maxCookieChunks; i++ {
		m.clearCookie(w, m.chunkName(i))
	}
	return nil
}

func (m *Manager) readSession(r *http.Request) (sessionData, bool) {
	var b strings.Builder
	for i := 0; i < maxCookieChunks; i++ {
		c, err := r.Cookie(m.chunkName(i))
		if err != nil || c.Value == "" {
			break
		}
		b.WriteString(c.Value)
	}
	if b.Len() == 0 {
		return sessionData{}, false
	}
	var sess sessionData
	if err := m.openJSON(b.String(), "session", &sess); err != nil {
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
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.cookieSecure,
		SameSite: m.sameSite,
	})
}

func (m *Manager) chunkName(index int) string {
	if index == 0 {
		return m.cookieName
	}
	return m.cookieName + "_" + strconv.Itoa(index)
}

func (m *Manager) sealJSON(v any, aad string) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := m.aead.Seal(nonce, nonce, plain, []byte(aad))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (m *Manager) openJSON(encoded, aad string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) < m.aead.NonceSize() {
		return errors.New("invalid encrypted cookie")
	}
	nonce := raw[:m.aead.NonceSize()]
	ciphertext := raw[m.aead.NonceSize():]
	plain, err := m.aead.Open(nil, nonce, ciphertext, []byte(aad))
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
	if rd == "" || !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") ||
		strings.ContainsAny(rd, "\r\n\x00") {
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
