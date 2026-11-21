package oidc

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// RevocationStore persists backchannel-logout revocations across multiple proxy
// replicas (e.g. Redis / Valkey).
type RevocationStore interface {
	Revoke(ctx context.Context, key string, ttl time.Duration) error
	IsRevoked(ctx context.Context, key string) (bool, error)
}

// RedisRevocationStore is a zero-dependency RESP2 client for sharing
// backchannel-logout revocations across replicas via Redis or Valkey.
type RedisRevocationStore struct {
	addr      string
	password  string
	keyPrefix string
	tlsConfig *tls.Config
	timeout   time.Duration
}

// NewRedisRevocationStore constructs a RESP2 revocation store.
// When tlsCfg is non-nil, connections use TLS 1.2+.
func NewRedisRevocationStore(addr, password string, tlsCfg *tls.Config) (*RedisRevocationStore, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, errors.New("redis address is required")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("invalid redis address %q: %w", addr, err)
	}
	var clonedTLS *tls.Config
	if tlsCfg != nil {
		clonedTLS = tlsCfg.Clone()
		if clonedTLS.MinVersion < tls.VersionTLS12 {
			clonedTLS.MinVersion = tls.VersionTLS12
		}
	}
	return &RedisRevocationStore{
		addr:      addr,
		password:  password,
		keyPrefix: "gocloak:revoked:",
		tlsConfig: clonedTLS,
		timeout:   2 * time.Second,
	}, nil
}

func (s *RedisRevocationStore) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: s.timeout}
	if s.tlsConfig != nil {
		td := tls.Dialer{NetDialer: &d, Config: s.tlsConfig}
		return td.DialContext(ctx, "tcp", s.addr)
	}
	return d.DialContext(ctx, "tcp", s.addr)
}

func (s *RedisRevocationStore) exec(ctx context.Context, args ...string) (string, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(s.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if s.password != "" {
		if err := writeRESPCommand(rw.Writer, "AUTH", s.password); err != nil {
			return "", err
		}
		if err := rw.Flush(); err != nil {
			return "", err
		}
		if _, err := readRESPReply(rw.Reader); err != nil {
			return "", err
		}
	}
	if err := writeRESPCommand(rw.Writer, args...); err != nil {
		return "", err
	}
	if err := rw.Flush(); err != nil {
		return "", err
	}
	return readRESPReply(rw.Reader)
}

// Revoke stores a revoked SID or sub key with TTL seconds in Redis/Valkey.
func (s *RedisRevocationStore) Revoke(ctx context.Context, key string, ttl time.Duration) error {
	secs := int64(ttl.Seconds())
	if secs < 1 {
		secs = 1
	}
	_, err := s.exec(ctx, "SET", s.keyPrefix+key, "1", "EX", strconv.FormatInt(secs, 10))
	return err
}

// IsRevoked checks whether key exists in Redis/Valkey.
func (s *RedisRevocationStore) IsRevoked(ctx context.Context, key string) (bool, error) {
	reply, err := s.exec(ctx, "EXISTS", s.keyPrefix+key)
	if err != nil {
		return false, err
	}
	return reply == "1", nil
}

func writeRESPCommand(w *bufio.Writer, args ...string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, a := range args {
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(a), a); err != nil {
			return err
		}
	}
	return nil
}

func readRESPReply(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return "", errors.New("empty RESP reply")
	}
	switch line[0] {
	case '+', ':':
		return line[1:], nil
	case '-':
		return "", errors.New("redis command failed")
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", err
		}
		if n < 0 {
			return "", nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	default:
		return "", errors.New("unsupported RESP reply")
	}
}
