package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMultiVerifierAndRejectionReasons(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issA := "https://kc.example.test/realms/tenant-a"
	issB := "https://kc.example.test/realms/tenant-b"
	vA, err := NewWithOptions(testKeys{key: &keyA.PublicKey}, Options{
		Issuer:             issA,
		Audience:           "api",
		RequiredRealmRoles: []string{"reader"},
	})
	if err != nil {
		t.Fatal(err)
	}
	vB, err := NewWithOptions(testKeys{key: &keyB.PublicKey}, Options{
		Issuer:             issB,
		Audience:           "api",
		RequiredRealmRoles: []string{"reader"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mv, err := NewMultiVerifier(map[string]*Verifier{issA: vA, issB: vB})
	if err != nil {
		t.Fatal(err)
	}

	claimsA := validClaims()
	claimsA["iss"] = issA
	claimsA["aud"] = "api"
	tokA := signed(t, jwt.SigningMethodES256, keyA, claimsA, nil)
	idA, err := mv.Verify(context.Background(), tokA)
	if err != nil || idA.User != "alice" {
		t.Fatalf("tenant A verify failed: %#v %v", idA, err)
	}

	claimsB := validClaims()
	claimsB["iss"] = issB
	claimsB["aud"] = "api"
	claimsB["preferred_username"] = "bob"
	tokB := signed(t, jwt.SigningMethodES256, keyB, claimsB, nil)
	idB, err := mv.Verify(context.Background(), tokB)
	if err != nil || idB.User != "bob" {
		t.Fatalf("tenant B verify failed: %#v %v", idB, err)
	}

	// Unlisted issuer is rejected with issuer_not_allowed.
	claimsEvil := validClaims()
	claimsEvil["iss"] = "https://kc.example.test/realms/evil"
	claimsEvil["aud"] = "api"
	tokEvil := signed(t, jwt.SigningMethodES256, keyA, claimsEvil, nil)
	_, err = mv.Verify(context.Background(), tokEvil)
	if err == nil || Reason(err) != "issuer_not_allowed" || strings.Contains(err.Error(), "evil") {
		t.Fatalf("expected issuer_not_allowed without leaking issuer, got err=%v reason=%q", err, Reason(err))
	}

	// Cross-tenant key mismatch fails with invalid_signature.
	tokCross := signed(t, jwt.SigningMethodES256, keyB, claimsA, nil)
	_, err = mv.Verify(context.Background(), tokCross)
	if err == nil || Reason(err) != "invalid_signature" {
		t.Fatalf("expected invalid_signature, got err=%v reason=%q", err, Reason(err))
	}

	// Specific diagnostic reasons for expired, audience_mismatch, missing_realm_role.
	expClaims := validClaims()
	expClaims["iss"] = issA
	expClaims["aud"] = "api"
	expClaims["exp"] = time.Now().Add(-time.Minute).Unix()
	if _, err := mv.Verify(context.Background(), signed(t, jwt.SigningMethodES256, keyA, expClaims, nil)); Reason(err) != "expired" {
		t.Fatalf("expected expired reason, got %q", Reason(err))
	}

	audClaims := validClaims()
	audClaims["iss"] = issA
	audClaims["aud"] = "wrong-api"
	if _, err := mv.Verify(context.Background(), signed(t, jwt.SigningMethodES256, keyA, audClaims, nil)); Reason(err) != "audience_mismatch" {
		t.Fatalf("expected audience_mismatch reason, got %q", Reason(err))
	}

	roleClaims := validClaims()
	roleClaims["iss"] = issA
	roleClaims["aud"] = "api"
	roleClaims["realm_access"] = map[string]any{"roles": []string{"other"}}
	_, err = mv.Verify(context.Background(), signed(t, jwt.SigningMethodES256, keyA, roleClaims, nil))
	if !errors.Is(err, ErrForbidden) || Reason(err) != "missing_realm_role" {
		t.Fatalf("expected ErrForbidden + missing_realm_role, got err=%v reason=%q", err, Reason(err))
	}
}
