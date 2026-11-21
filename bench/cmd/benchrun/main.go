// Command benchrun is a repeatable HTTP benchmark runner and mock Keycloak/upstream
// harness for isolated, cross-language competitor, and live-Keycloak benchmarks.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	json "encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type benchResult struct {
	Name       string  `json:"name"`
	Mode       string  `json:"mode"`
	TokenMode  string  `json:"token_mode"`
	RPS        float64 `json:"rps"`
	P50Ms      float64 `json:"p50_ms"`
	P95Ms      float64 `json:"p95_ms"`
	P99Ms      float64 `json:"p99_ms"`
	MaxMs      float64 `json:"max_ms"`
	Errors     int64   `json:"errors"`
	TotalReqs  int64   `json:"total_reqs"`
	IdleRSSMB  float64 `json:"idle_rss_mb"`
	LoadRSSMB  float64 `json:"load_rss_mb"`
	DurationMs int64   `json:"duration_ms"`
}

type mockInfo struct {
	Issuer      string `json:"issuer"`
	JWKSURL     string `json:"jwks_url"`
	UpstreamURL string `json:"upstream_url"`
	Audience    string `json:"audience"`
	ClientID    string `json:"client_id"`
	Token       string `json:"token"`
	TokensFile  string `json:"tokens_file,omitempty"`
}

func main() {
	mode := flag.String("mode", "load", "mode: mocks | load | keycloak-token")
	name := flag.String("name", "proxy", "label for result output")
	benchMode := flag.String("bench-mode", "forward_auth", "label: forward_auth | reverse_proxy | introspection")
	targetURL := flag.String("target-url", "", "target proxy URL to benchmark")
	targetPID := flag.Int("target-pid", 0, "optional PID of target proxy for RSS measurement")
	token := flag.String("token", "", "single bearer token (warm mode)")
	tokensFile := flag.String("tokens-file", "", "newline-delimited bearer tokens file (cold mode)")
	concurrency := flag.Int("c", 32, "number of concurrent workers")
	duration := flag.Duration("d", 5*time.Second, "measurement duration")
	warmup := flag.Duration("w", 1*time.Second, "warmup duration")
	jsonOut := flag.Bool("json", false, "output JSON instead of summary line")

	// Mock server flags
	kcAddr := flag.String("kc-addr", "127.0.0.1:18081", "mock Keycloak listen address")
	upAddr := flag.String("up-addr", "127.0.0.1:18082", "mock upstream listen address")
	coldCount := flag.Int("cold-tokens", 2000, "number of unique RS256 JWTs to generate for cold mode")
	infoFile := flag.String("info-file", "", "write mock server JSON info to this path")
	outTokensFile := flag.String("out-tokens-file", "", "write generated cold tokens to this path")

	// Live Keycloak token fetch flags
	kcURL := flag.String("keycloak-url", "", "real Keycloak base URL, e.g. http://127.0.0.1:8081")
	kcRealm := flag.String("realm", "bench", "Keycloak realm name")
	kcClientID := flag.String("client-id", "bench-api", "Keycloak client ID")
	kcClientSecret := flag.String("client-secret", "bench-secret", "Keycloak client secret")
	kcUser := flag.String("username", "benchuser", "Keycloak username")
	kcPass := flag.String("password", "benchpass", "Keycloak password")

	flag.Parse()

	switch *mode {
	case "mocks":
		if err := runMocks(*kcAddr, *upAddr, *coldCount, *infoFile, *outTokensFile); err != nil {
			fmt.Fprintf(os.Stderr, "mocks error: %v\n", err)
			os.Exit(1)
		}
	case "load":
		if *targetURL == "" {
			fmt.Fprintln(os.Stderr, "-target-url is required in load mode")
			os.Exit(2)
		}
		var tokens []string
		tokenMode := "warm"
		if *tokensFile != "" {
			data, err := os.ReadFile(*tokensFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read tokens file: %v\n", err)
				os.Exit(1)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if s := strings.TrimSpace(line); s != "" {
					tokens = append(tokens, s)
				}
			}
			tokenMode = fmt.Sprintf("cold(%d)", len(tokens))
		} else if *token != "" {
			tokens = []string{*token}
		} else {
			fmt.Fprintln(os.Stderr, "-token or -tokens-file is required in load mode")
			os.Exit(2)
		}
		res := runLoad(*name, *benchMode, tokenMode, *targetURL, *targetPID, tokens, *concurrency, *warmup, *duration)
		if *jsonOut {
			b, _ := json.Marshal(res)
			fmt.Println(string(b))
		} else {
			fmt.Printf("| %s | %s | %s | %.0f | %.2f ms | %.2f ms | %.2f ms | %.1f MB | %.1f MB | %d |\n",
				res.Name, res.Mode, res.TokenMode, res.RPS, res.P50Ms, res.P95Ms, res.P99Ms, res.IdleRSSMB, res.LoadRSSMB, res.Errors)
		}
	case "keycloak-token":
		tok, err := fetchKeycloakToken(*kcURL, *kcRealm, *kcClientID, *kcClientSecret, *kcUser, *kcPass)
		if err != nil {
			fmt.Fprintf(os.Stderr, "keycloak token error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(tok)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
}

func runMocks(kcAddr, upAddr string, coldCount int, infoFile, outTokensFile string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	const kid = "bench-rsa-1"
	const audience = "bench-api"
	const clientID = "bench-api"

	kcLn, err := net.Listen("tcp", kcAddr)
	if err != nil {
		return err
	}
	upLn, err := net.Listen("tcp", upAddr)
	if err != nil {
		_ = kcLn.Close()
		return err
	}

	issuer := "http://" + kcLn.Addr().String() + "/realms/bench"
	jwksURL := issuer + "/protocol/openid-connect/certs"
	upstreamURL := "http://" + upLn.Addr().String()

	jwksBody, err := marshalJWKS(kid, &key.PublicKey)
	if err != nil {
		return err
	}
	discoveryBody, err := json.Marshal(map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/protocol/openid-connect/auth",
		"token_endpoint":         issuer + "/protocol/openid-connect/token",
		"userinfo_endpoint":      issuer + "/protocol/openid-connect/userinfo",
		"jwks_uri":               jwksURL,
		"introspection_endpoint": issuer + "/protocol/openid-connect/token/introspect",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
	if err != nil {
		return err
	}
	introspectBody := []byte(`{"active":true,"sub":"user-123","preferred_username":"alice"}`)

	kcMux := http.NewServeMux()
	kcMux.HandleFunc("/realms/bench/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(discoveryBody)
	})
	kcMux.HandleFunc("/realms/bench/protocol/openid-connect/certs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	})
	kcMux.HandleFunc("/realms/bench/protocol/openid-connect/token/introspect", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(introspectBody)
	})

	okBytes := []byte("ok")
	upHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write(okBytes)
	})

	kcSrv := &http.Server{Handler: kcMux, ReadHeaderTimeout: 5 * time.Second}
	upSrv := &http.Server{Handler: upHandler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = kcSrv.Serve(kcLn) }()
	go func() { _ = upSrv.Serve(upLn) }()

	warmToken, err := signRS256JWT(key, kid, issuer, audience, "warm-0")
	if err != nil {
		return err
	}

	if outTokensFile != "" && coldCount > 0 {
		var sb strings.Builder
		sb.Grow(coldCount * 1024)
		for i := range coldCount {
			tok, err := signRS256JWT(key, kid, issuer, audience, fmt.Sprintf("cold-%d", i))
			if err != nil {
				return err
			}
			sb.WriteString(tok)
			sb.WriteByte('\n')
		}
		if err := os.WriteFile(outTokensFile, []byte(sb.String()), 0o600); err != nil {
			return err
		}
	}

	info := mockInfo{
		Issuer:      issuer,
		JWKSURL:     jwksURL,
		UpstreamURL: upstreamURL,
		Audience:    audience,
		ClientID:    clientID,
		Token:       warmToken,
		TokensFile:  outTokensFile,
	}
	infoBytes, err := json.Marshal(info)
	if err != nil {
		return err
	}
	if infoFile != "" {
		if err := os.WriteFile(infoFile, infoBytes, 0o600); err != nil {
			return err
		}
	} else {
		fmt.Println(string(infoBytes))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	_ = kcSrv.Close()
	_ = upSrv.Close()
	return nil
}

func marshalJWKS(kid string, pub *rsa.PublicKey) ([]byte, error) {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kid": kid,
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"n":   n,
			"e":   e,
		}},
	})
}

func signRS256JWT(key *rsa.PrivateKey, kid, issuer, audience, jti string) (string, error) {
	now := time.Now()
	hdrBytes, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	})
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(map[string]any{
		"jti":                jti,
		"iss":                issuer,
		"aud":                audience,
		"sub":                "user-123",
		"typ":                "Bearer",
		"azp":                audience,
		"iat":                now.Add(-5 * time.Second).Unix(),
		"nbf":                now.Add(-5 * time.Second).Unix(),
		"exp":                now.Add(2 * time.Hour).Unix(),
		"preferred_username": "alice",
		"email":              "alice@example.test",
		"email_verified":     true,
		"groups":             []string{"engineering", "platform"},
		"realm_access":       map[string]any{"roles": []string{"reader", "user"}},
		"resource_access": map[string]any{
			audience: map[string]any{"roles": []string{"api-read"}},
		},
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func runLoad(name, mode, tokenMode, targetURL string, targetPID int, tokens []string, concurrency int, warmup, duration time.Duration) benchResult {
	idleRSS := readRSSMB(targetPID)

	transport := &http.Transport{
		MaxIdleConns:        concurrency * 2,
		MaxIdleConnsPerHost: concurrency * 2,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authHeaders := make([]string, len(tokens))
	for i, t := range tokens {
		authHeaders[i] = "Bearer " + t
	}

	// Warmup phase
	if warmup > 0 {
		runWorkers(client, targetURL, authHeaders, concurrency, warmup, false)
	}

	// Measurement phase
	var peakRSS atomic.Int64
	rssStop := make(chan struct{})
	if targetPID > 0 {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-rssStop:
					return
				case <-t.C:
					kb := readRSSKB(targetPID)
					for {
						cur := peakRSS.Load()
						if kb <= cur || peakRSS.CompareAndSwap(cur, kb) {
							break
						}
					}
				}
			}
		}()
	}

	start := time.Now()
	latencies, total, errs := runWorkers(client, targetURL, authHeaders, concurrency, duration, true)
	elapsed := time.Since(start)
	close(rssStop)

	loadRSS := float64(peakRSS.Load()) / 1024.0
	if loadRSS == 0 {
		loadRSS = readRSSMB(targetPID)
	}

	slices.Sort(latencies)
	p50, p95, p99, maxMs := 0.0, 0.0, 0.0, 0.0
	if n := len(latencies); n > 0 {
		p50 = float64(latencies[n*50/100]) / 1e6
		p95 = float64(latencies[n*95/100]) / 1e6
		p99 = float64(latencies[min(n*99/100, n-1)]) / 1e6
		maxMs = float64(latencies[n-1]) / 1e6
	}

	return benchResult{
		Name:       name,
		Mode:       mode,
		TokenMode:  tokenMode,
		RPS:        float64(total) / elapsed.Seconds(),
		P50Ms:      p50,
		P95Ms:      p95,
		P99Ms:      p99,
		MaxMs:      maxMs,
		Errors:     errs,
		TotalReqs:  total,
		IdleRSSMB:  idleRSS,
		LoadRSSMB:  loadRSS,
		DurationMs: elapsed.Milliseconds(),
	}
}

func runWorkers(client *http.Client, targetURL string, authHeaders []string, concurrency int, dur time.Duration, record bool) ([]int64, int64, int64) {
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	var total atomic.Int64
	var errs atomic.Int64
	var tokenIdx atomic.Uint64

	perWorker := make([][]int64, concurrency)
	for w := range concurrency {
		if record {
			perWorker[w] = make([]int64, 0, 4096)
		}
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			buf := perWorker[id]
			nTok := uint64(len(authHeaders))
			for time.Now().Before(deadline) {
				idx := tokenIdx.Add(1) - 1
				req, err := http.NewRequest(http.MethodGet, targetURL, nil)
				if err != nil {
					errs.Add(1)
					continue
				}
				req.Header.Set("Authorization", authHeaders[idx%nTok])
				t0 := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errs.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				dt := time.Since(t0).Nanoseconds()
				if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
					errs.Add(1)
					continue
				}
				total.Add(1)
				if record {
					buf = append(buf, dt)
				}
			}
			perWorker[id] = buf
		}(w)
	}
	wg.Wait()

	if !record {
		return nil, total.Load(), errs.Load()
	}
	all := make([]int64, 0, int(total.Load()))
	for _, b := range perWorker {
		all = append(all, b...)
	}
	return all, total.Load(), errs.Load()
}

func readRSSKB(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb
			}
		}
	}
	return 0
}

func readRSSMB(pid int) float64 {
	return float64(readRSSKB(pid)) / 1024.0
}

func fetchKeycloakToken(baseURL, realm, clientID, clientSecret, username, password string) (string, error) {
	if baseURL == "" {
		return "", fmt.Errorf("keycloak-url is required")
	}
	tokenURL := strings.TrimRight(baseURL, "/") + "/realms/" + realm + "/protocol/openid-connect/token"
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("missing access_token in Keycloak response")
	}
	return out.AccessToken, nil
}
