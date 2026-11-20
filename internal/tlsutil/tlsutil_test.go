package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientConfigDefault(t *testing.T) {
	cfg, err := ClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.RootCAs != nil {
		t.Fatalf("unexpected default config: %+v", cfg)
	}
}

func TestClientConfigCustomCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ClientConfig(caPath)
	if err != nil {
		t.Fatalf("ClientConfig failed: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.RootCAs == nil {
		t.Fatalf("unexpected custom CA config: %+v", cfg)
	}
}

func TestClientConfigErrors(t *testing.T) {
	if _, err := ClientConfig(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected error for missing CA file")
	}
	badPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badPath, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientConfig(badPath); err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestClientConfigWithCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := ClientConfigWithCert("", certPath, keyPath)
	if err != nil {
		t.Fatalf("ClientConfigWithCert failed: %v", err)
	}
	if len(cfg.Certificates) != 1 || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected mTLS config: %+v", cfg)
	}
	if _, err := ClientConfigWithCert("", certPath, ""); err == nil {
		t.Error("expected error when key is missing")
	}
	if _, err := ClientConfigWithCert("", "", keyPath); err == nil {
		t.Error("expected error when cert is missing")
	}
	if _, err := ClientConfigWithCert("", filepath.Join(dir, "missing.crt"), keyPath); err == nil {
		t.Error("expected error for missing cert file")
	}
}
