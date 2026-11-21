package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSignedPair(t *testing.T, dir, prefix string, serial int64) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "proxy.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, prefix+".crt")
	keyPath := filepath.Join(dir, prefix+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestCertReloaderLiveRotation(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedPair(t, dir, "server", 101)

	tlsCfg, reloader, err := ServerConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := tlsCfg.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf1, err := x509.ParseCertificate(c1.Certificate[0])
	if err != nil || leaf1.SerialNumber.Int64() != 101 {
		t.Fatalf("expected serial 101, got %v (err=%v)", leaf1.SerialNumber, err)
	}

	// Rotate certificate files on disk and reload.
	writeSelfSignedPair(t, dir, "server", 202)
	if err := reloader.Reload(); err != nil {
		t.Fatal(err)
	}
	c2, err := tlsCfg.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := x509.ParseCertificate(c2.Certificate[0])
	if err != nil || leaf2.SerialNumber.Int64() != 202 {
		t.Fatalf("expected rotated serial 202, got %v (err=%v)", leaf2.SerialNumber, err)
	}
}
