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
	return ClientConfigWithCert(caFile, "", "")
}

// ClientConfigWithCert returns a TLS 1.2+ client configuration with optional
// custom CA bundle and optional mTLS client certificate/key pair.
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
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
