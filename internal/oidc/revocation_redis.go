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
	"sync"
	"time"
)

const (
	maxRESPReplyBytes = 64 << 10 // 64 KiB cap prevents OOM from malformed/malicious replies
	maxRESPArrayLen   = 16
	maxRedisPoolSize  = 32
	redisIdleTimeout  = 60 * time.Second
)

// RevocationStore persists backchannel-logout revocations across multiple proxy
// replicas (e.g. Redis / Valkey).
type RevocationStore interface {
	// Revoke records a revocation entry with an opaque value (e.g. "1" for sid,
	// Unix timestamp for sub) and expiration TTL.
	Revoke(ctx context.Context, key, value string, ttl time.Duration) error
	// IsRevoked checks sidKey and/or subKey in a single round-trip where possible.
	// For subKey, sessions issued strictly after the stored revocation timestamp
	// are allowed so users can immediately log back in after a subject-wide logout.
	IsRevoked(ctx context.Context, sidKey, subKey string, issuedAt int64) (bool, error)
}

type pooledRedisConn struct {
	conn     net.Conn
	rw       *bufio.ReadWriter
	lastUsed time.Time
}

// RedisRevocationStore is a zero-dependency, pooled RESP2 client for sharing
// backchannel-logout revocations across replicas via Redis or Valkey.
type RedisRevocationStore struct {
	addr      string
	password  string
	keyPrefix string
	tlsConfig *tls.Config
	timeout   time.Duration

	poolMu sync.Mutex
	pool   []*pooledRedisConn
	closed bool
}

// NewRedisRevocationStore constructs a pooled RESP2 revocation store.
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

// Close closes all idle pooled connections.
func (s *RedisRevocationStore) Close() error {
	s.poolMu.Lock()
	s.closed = true
	conns := s.pool
	s.pool = nil
	s.poolMu.Unlock()
	for _, pc := range conns {
		_ = pc.conn.Close()
	}
	return nil
}

func (s *RedisRevocationStore) getConn(ctx context.Context) (*pooledRedisConn, bool, error) {
	now := time.Now()
	s.poolMu.Lock()
	for len(s.pool) > 0 {
		pc := s.pool[len(s.pool)-1]
		s.pool = s.pool[:len(s.pool)-1]
		if now.Sub(pc.lastUsed) <= redisIdleTimeout {
			s.poolMu.Unlock()
			return pc, true, nil
		}
		_ = pc.conn.Close()
	}
	s.poolMu.Unlock()

	pc, err := s.dialAndAuth(ctx)
	return pc, false, err
}

func (s *RedisRevocationStore) putConn(pc *pooledRedisConn) {
	pc.lastUsed = time.Now()
	s.poolMu.Lock()
	if s.closed || len(s.pool) >= maxRedisPoolSize {
		s.poolMu.Unlock()
		_ = pc.conn.Close()
		return
	}
	s.pool = append(s.pool, pc)
	s.poolMu.Unlock()
}

func (s *RedisRevocationStore) dialAndAuth(ctx context.Context) (*pooledRedisConn, error) {
	d := net.Dialer{Timeout: s.timeout}
	var (
		conn net.Conn
		err  error
	)
	if s.tlsConfig != nil {
		td := tls.Dialer{NetDialer: &d, Config: s.tlsConfig}
		conn, err = td.DialContext(ctx, "tcp", s.addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", s.addr)
	}
	if err != nil {
		return nil, err
	}
	pc := &pooledRedisConn{
		conn: conn,
		rw:   bufio.NewReadWriter(bufio.NewReaderSize(conn, 4096), bufio.NewWriterSize(conn, 4096)),
	}
	if s.password != "" {
		deadline := s.deadline(ctx)
		_ = conn.SetDeadline(deadline)
		if err := writeRESPCommand(pc.rw.Writer, "AUTH", s.password); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if err := pc.rw.Flush(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := readRESPReply(pc.rw.Reader); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return pc, nil
}

func (s *RedisRevocationStore) deadline(ctx context.Context) time.Time {
	dl := time.Now().Add(s.timeout)
	if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(dl) {
		return ctxDL
	}
	return dl
}

func (s *RedisRevocationStore) exec(ctx context.Context, args ...string) ([]string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		pc, fromPool, err := s.getConn(ctx)
		if err != nil {
			return nil, err
		}
		_ = pc.conn.SetDeadline(s.deadline(ctx))
		if err := writeRESPCommand(pc.rw.Writer, args...); err != nil {
			_ = pc.conn.Close()
			if fromPool && attempt == 0 {
				continue
			}
			return nil, err
		}
		if err := pc.rw.Flush(); err != nil {
			_ = pc.conn.Close()
			if fromPool && attempt == 0 {
				continue
			}
			return nil, err
		}
		reply, err := readRESPReply(pc.rw.Reader)
		if err != nil {
			_ = pc.conn.Close()
			if fromPool && attempt == 0 {
				continue
			}
			return nil, err
		}
		s.putConn(pc)
		return reply, nil
	}
	return nil, errors.New("redis command failed after retry")
}

// Revoke stores a revoked SID or sub key with value and TTL seconds in Redis/Valkey.
func (s *RedisRevocationStore) Revoke(ctx context.Context, key, value string, ttl time.Duration) error {
	secs := int64(ttl.Seconds())
	if secs < 1 {
		secs = 1
	}
	if value == "" {
		value = "1"
	}
	_, err := s.exec(ctx, "SET", s.keyPrefix+key, value, "EX", strconv.FormatInt(secs, 10))
	return err
}

// IsRevoked checks sidKey and/or subKey in a single Redis round-trip using MGET.
func (s *RedisRevocationStore) IsRevoked(ctx context.Context, sidKey, subKey string, issuedAt int64) (bool, error) {
	if sidKey == "" && subKey == "" {
		return false, nil
	}
	var args []string
	hasSID := sidKey != ""
	hasSub := subKey != ""
	args = append(args, "MGET")
	if hasSID {
		args = append(args, s.keyPrefix+sidKey)
	}
	if hasSub {
		args = append(args, s.keyPrefix+subKey)
	}
	vals, err := s.exec(ctx, args...)
	if err != nil {
		return false, err
	}
	expected := 0
	if hasSID {
		expected++
	}
	if hasSub {
		expected++
	}
	if len(vals) != expected {
		return false, errors.New("unexpected MGET reply length")
	}
	idx := 0
	if hasSID {
		if vals[idx] != "" {
			return true, nil
		}
		idx++
	}
	if hasSub && vals[idx] != "" {
		revokedAt, err := strconv.ParseInt(vals[idx], 10, 64)
		if err != nil {
			// Legacy/opaque value: fail closed.
			return true, nil
		}
		if issuedAt == 0 || issuedAt <= revokedAt {
			return true, nil
		}
	}
	return false, nil
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

func readRESPLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		if len(line)+len(chunk) > maxRESPReplyBytes {
			return "", errors.New("RESP line exceeds maximum length")
		}
		line = append(line, chunk...)
		if !isPrefix {
			return string(line), nil
		}
	}
}

func readRESPReply(r *bufio.Reader) ([]string, error) {
	line, err := readRESPLine(r)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, errors.New("empty RESP reply")
	}
	switch line[0] {
	case '+', ':':
		return []string{line[1:]}, nil
	case '-':
		return nil, errors.New("redis command failed")
	case '$':
		val, err := readRESPBulkString(r, line[1:])
		if err != nil {
			return nil, err
		}
		return []string{val}, nil
	case '*':
		count, err := strconv.Atoi(line[1:])
		if err != nil || count < 0 || count > maxRESPArrayLen {
			return nil, errors.New("invalid RESP array length")
		}
		out := make([]string, count)
		for i := 0; i < count; i++ {
			elem, err := readRESPReply(r)
			if err != nil || len(elem) != 1 {
				return nil, errors.New("invalid RESP array element")
			}
			out[i] = elem[0]
		}
		return out, nil
	default:
		return nil, errors.New("unsupported RESP reply")
	}
}

func readRESPBulkString(r *bufio.Reader, lenStr string) (string, error) {
	n, err := strconv.Atoi(lenStr)
	if err != nil {
		return "", err
	}
	if n < 0 {
		return "", nil
	}
	if n > maxRESPReplyBytes {
		return "", errors.New("RESP bulk string exceeds maximum length")
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	if buf[n] != '\r' || buf[n+1] != '\n' {
		return "", errors.New("malformed RESP bulk string terminator")
	}
	return string(buf[:n]), nil
}
