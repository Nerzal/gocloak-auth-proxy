package oidc

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDualKeyCookieRotation(t *testing.T) {
	oldSecret := strings.Repeat("a", 32)
	newSecret := strings.Repeat("b", 32)

	oldMgr, err := New(Config{
		Issuer:            "http://localhost/realms/demo",
		ClientID:          "app",
		RedirectURL:       "http://localhost/oauth2/callback",
		CookieSecret:      oldSecret,
		CookieSecure:      false,
		SessionMaxAge:     time.Hour,
		CookieSameSite:    0,
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

func TestRedisRevocationStoreRESP2PoolAndSubTimestamp(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var (
		mu       sync.Mutex
		store    = make(map[string]string)
		connCnt  atomic.Int64
	)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connCnt.Add(1)
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
					case "MGET":
						keys := args[1:]
						var sb strings.Builder
						fmt.Fprintf(&sb, "*%d\r\n", len(keys))
						mu.Lock()
						for _, k := range keys {
							if v, ok := store[k]; ok {
								fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(v), v)
							} else {
								sb.WriteString("$-1\r\n")
							}
						}
						mu.Unlock()
						_, _ = c.Write([]byte(sb.String()))
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
	defer func() { _ = rs.Close() }()

	// Initially not revoked.
	revoked, err := rs.IsRevoked(context.Background(), "sid:s1", "sub:u1", 1000)
	if err != nil || revoked {
		t.Fatalf("expected not revoked initially, got revoked=%v err=%v", revoked, err)
	}

	// Revoke sid:s1 and verify single-RTT MGET catches it.
	if err := rs.Revoke(context.Background(), "sid:s1", "1", time.Minute); err != nil {
		t.Fatalf("Revoke sid failed: %v", err)
	}
	revoked, err = rs.IsRevoked(context.Background(), "sid:s1", "sub:u1", 1000)
	if err != nil || !revoked {
		t.Fatalf("expected sid revoked=true, got revoked=%v err=%v", revoked, err)
	}

	// Revoke sub:u2 at timestamp 2000; old session (1500) is revoked, new session (2001) after re-login is allowed!
	if err := rs.Revoke(context.Background(), "sub:u2", strconv.FormatInt(2000, 10), time.Minute); err != nil {
		t.Fatalf("Revoke sub failed: %v", err)
	}
	revoked, err = rs.IsRevoked(context.Background(), "sid:other", "sub:u2", 1500)
	if err != nil || !revoked {
		t.Fatalf("expected old session issued before sub revocation to be revoked, got revoked=%v err=%v", revoked, err)
	}
	revoked, err = rs.IsRevoked(context.Background(), "sid:new", "sub:u2", 2001)
	if err != nil || revoked {
		t.Fatalf("expected new session issued after sub revocation to be allowed, got revoked=%v err=%v", revoked, err)
	}

	// Verify connection pooling reused a single TCP connection for all sequential commands.
	if got := connCnt.Load(); got != 1 {
		t.Fatalf("expected 1 pooled TCP connection, got %d", got)
	}
}

func TestRedisRevocationStoreRejectsOversizedBulkReply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Respond with an absurd bulk string length that would OOM an unbounded reader.
		_, _ = conn.Write([]byte("*1\r\n$999999999\r\n"))
	}()

	rs, err := NewRedisRevocationStore(ln.Addr().String(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()

	if _, err := rs.IsRevoked(context.Background(), "sid:s1", "", 0); err == nil {
		t.Fatal("expected error for oversized RESP bulk string reply")
	}
}
