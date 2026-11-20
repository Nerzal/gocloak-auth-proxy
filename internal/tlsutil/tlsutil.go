// Package tlsutil builds hardened TLS configurations with optional custom CAs.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ClientConfig returns a TLS 1.2+ client configuration. When caFile is
// non-empty, its PEM-encoded certificates are added to the trusted root pool.
func ClientConfig(caFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if caFile == "" {
		return cfg, nil
	}
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
	return cfg, nil
}
