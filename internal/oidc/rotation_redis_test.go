package oidc

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDualKeyCookieRotation(t *testing.T) {
	oldSecret := strings.Repeat("a", 32)
	newSecret := strings.Repeat("b", 32)

	oldMgr, err := New(Config{
		Issuer:           "http://localhost/realms/demo",
		ClientID:         "app",
		RedirectURL:      "http://localhost/oauth2/callback",
		CookieSecret:     oldSecret,
		CookieSecure:     false,
		SessionMaxAge:    time.Hour,
		CookieSameSite:   0,
		AllowedAlgorithms: []string{"ES256"},
	}, stubVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	newMgr, err := New(Config{
		Issuer:               "http://localhost/realms/demo",
		ClientID:             "app",
		RedirectURL:          "http://localhost/oauth2/callback",
		CookieSecret:         newSecret,
		CookieSecretPrevious: oldSecret,
		CookieSecure:         false,
		SessionMaxAge:        time.Hour,
	}, stubVerifier{})
	if err != nil {
		t.Fatal(err)
	}

	want := sessionData{AccessToken: "rotated-token", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	sealed, err := oldMgr.sealJSON(want, aadSession)
	if err != nil {
		t.Fatal(err)
	}

	var got sessionData
	if err := newMgr.openJSON(sealed, aadSession, &got); err != nil {
		t.Fatalf("expected new manager with CookieSecretPrevious to decrypt old cookie: %v", err)
	}
	if got.AccessToken != want.AccessToken {
		t.Fatalf("got %q, want %q", got.AccessToken, want.AccessToken)
	}
}

func TestRedisRevocationStoreRESP2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var mu sync.Mutex
	store := make(map[string]string)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.HasPrefix(line, "*") {
						return
					}
					var n int
					_, _ = fmt.Sscanf(line, "*%d", &n)
					args := make([]string, 0, n)
					for range n {
						_, _ = r.ReadString('\n') // $len
						val, err := r.ReadString('\n')
						if err != nil {
							return
						}
						args = append(args, strings.TrimRight(val, "\r\n"))
					}
					switch strings.ToUpper(args[0]) {
					case "AUTH":
						_, _ = c.Write([]byte("+OK\r\n"))
					case "SET":
						mu.Lock()
						store[args[1]] = args[2]
						mu.Unlock()
						_, _ = c.Write([]byte("+OK\r\n"))
					case "EXISTS":
						mu.Lock()
						_, ok := store[args[1]]
						mu.Unlock()
						if ok {
							_, _ = c.Write([]byte(":1\r\n"))
						} else {
							_, _ = c.Write([]byte(":0\r\n"))
						}
					default:
						_, _ = c.Write([]byte("-ERR unknown\r\n"))
					}
				}
			}(conn)
		}
	}()

	rs, err := NewRedisRevocationStore(ln.Addr().String(), "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := rs.IsRevoked(context.Background(), "sid:s1")
	if err != nil || revoked {
		t.Fatalf("expected not revoked initially, got revoked=%v err=%v", revoked, err)
	}
	if err := rs.Revoke(context.Background(), "sid:s1", time.Minute); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	revoked, err = rs.IsRevoked(context.Background(), "sid:s1")
	if err != nil || !revoked {
		t.Fatalf("expected revoked=true, got revoked=%v err=%v", revoked, err)
	}
}
