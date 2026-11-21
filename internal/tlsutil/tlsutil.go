// Package tlsutil builds hardened TLS configurations with optional custom CAs
// and zero-downtime certificate reloading.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const defaultReloadCheckInterval = 5 * time.Second

// CertReloader maintains an atomically-swapped TLS certificate loaded from disk.
// It supports both automatic mtime-based reloading (e.g. cert-manager mounts)
// and explicit Reload() calls (e.g. on SIGHUP).
type CertReloader struct {
	certFile      string
	keyFile       string
	checkInterval time.Duration

	cert        atomic.Pointer[tls.Certificate]
	lastChecked atomic.Int64 // unix nanos

	mu          sync.Mutex
	certModTime time.Time
	keyModTime  time.Time
}

// NewCertReloader loads the initial certificate pair from disk and returns a reloader.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("certificate and key paths are required")
	}
	r := &CertReloader{
		certFile:      certFile,
		keyFile:       keyFile,
		checkInterval: defaultReloadCheckInterval,
	}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload unconditionally reloads the certificate pair from disk. On error,
// the previously loaded certificate remains active.
func (r *CertReloader) Reload() error {
	cInfo, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("stat certificate: %w", err)
	}
	kInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return fmt.Errorf("stat key: %w", err)
	}
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load key pair: %w", err)
	}
	r.mu.Lock()
	r.certModTime = cInfo.ModTime()
	r.keyModTime = kInfo.ModTime()
	r.mu.Unlock()
	r.cert.Store(&pair)
	r.lastChecked.Store(time.Now().UnixNano())
	return nil
}

func (r *CertReloader) current() (*tls.Certificate, error) {
	now := time.Now().UnixNano()
	last := r.lastChecked.Load()
	if now-last >= int64(r.checkInterval) && r.lastChecked.CompareAndSwap(last, now) {
		r.maybeReload()
	}
	cert := r.cert.Load()
	if cert == nil {
		return nil, errors.New("no TLS certificate loaded")
	}
	return cert, nil
}

func (r *CertReloader) maybeReload() {
	cInfo, err := os.Stat(r.certFile)
	if err != nil {
		return
	}
	kInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return
	}
	r.mu.Lock()
	changed := !cInfo.ModTime().Equal(r.certModTime) || !kInfo.ModTime().Equal(r.keyModTime)
	r.mu.Unlock()
	if !changed {
		return
	}
	_ = r.Reload()
}

// GetCertificate implements tls.Config.GetCertificate for TLS servers.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current()
}

// GetClientCertificate implements tls.Config.GetClientCertificate for mTLS clients.
func (r *CertReloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.current()
}

// ServerConfig builds a TLS 1.2+ server configuration backed by a live CertReloader.
func ServerConfig(certFile, keyFile string) (*tls.Config, *CertReloader, error) {
	reloader, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: reloader.GetCertificate,
	}, reloader, nil
}

// ClientConfig returns a TLS 1.2+ client configuration. When caFile is
// non-empty, its PEM-encoded certificates are added to the trusted root pool.
func ClientConfig(caFile string) (*tls.Config, error) {
	return ClientConfigWithCert(caFile, "", "")
}

// ClientConfigWithCert returns a TLS 1.2+ client configuration with optional
// custom CA bundle and optional auto-reloading mTLS client certificate/key pair.
func ClientConfigWithCert(caFile, certFile, keyFile string) (*tls.Config, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("client certificate and key must both be set")
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if caFile != "" {
		// #nosec G304 -- caFile is explicitly configured by the operator at startup.
		pemData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, errors.New("CA bundle contains no valid PEM certificates")
		}
		cfg.RootCAs = pool
	}
	if certFile != "" {
		reloader, err := NewCertReloader(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		if cur := reloader.cert.Load(); cur != nil {
			cfg.Certificates = []tls.Certificate{*cur}
		}
		cfg.GetClientCertificate = reloader.GetClientCertificate
	}
	return cfg, nil
}
