package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type testKeys struct {
	key any
	err error
}

func (k testKeys) Key(_ context.Context, _, _ string) (any, error) { return k.key, k.err }

func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": "issuer", "aud": []string{"audience", "other"}, "typ": "Bearer",
		"exp": now.Add(time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "iat": now.Add(-time.Minute).Unix(),
		"sub": "subject", "preferred_username": "alice", "email": "alice@example.test",
		"email_verified": true, "azp": "app", "scope": "openid profile api:read", "acr": "2",
		"organization": map[string]any{"acme": map[string]any{"id": "123"}},
		"tenant_id":    "tenant-42",
		"groups":       []string{"one", "two"},
		"realm_access": map[string]any{"roles": []string{"reader", "shared"}},
		"resource_access": map[string]any{
			"app":   map[string]any{"roles": []string{"writer", "shared"}},
			"other": map[string]any{"roles": []string{"other-role"}},
		},
	}
}

func signed(t testing.TB, method jwt.SigningMethod, key any, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = "key-1"
	for k, v := range header {
		token.Header[k] = v
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + raw
}

func verifier(t testing.TB, key any, skew time.Duration, realm, client []string) *Verifier {
	t.Helper()
	v, err := New(testKeys{key: key}, "issuer", "audience", skew, realm, client, "app")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerify(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		method jwt.SigningMethod
		key    any
		public any
	}{
		{"RS256", jwt.SigningMethodRS256, rsaKey, &rsaKey.PublicKey},
		{"ES256", jwt.SigningMethodES256, ecKey, &ecKey.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realm, client := []string{"reader"}, []string{"writer"}
			v := verifier(t, tc.public, 0, realm, client)
			realm[0], client[0] = "changed", "changed"
			tok := signed(t, tc.method, tc.key, validClaims(), nil)
			got, err := v.Verify(context.Background(), tok)
			want := Identity{
				User: "alice", Email: "alice@example.test",
				Subject: "subject", ACR: "2",
				Groups: []string{"one", "two"}, Roles: []string{"reader", "shared", "writer"},
				RealmRoles: []string{"reader", "shared"}, ClientRoles: []string{"writer", "shared"},
				RawToken: strings.TrimPrefix(tok, "Bearer "),
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, want)
			}
			// Standard Keycloak access tokens omit nbf by default.
			noNbf := validClaims()
			delete(noNbf, "nbf")
			if _, err := v.Verify(context.Background(), signed(t, tc.method, tc.key, noNbf, nil)); err != nil {
				t.Fatalf("rejected token without nbf: %v", err)
			}
		})
	}
}

func TestVerifyRejectsInvalidTokens(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := verifier(t, &key.PublicKey, 0, nil, nil)
	tests := []struct {
		name   string
		mutate func(jwt.MapClaims)
		header map[string]any
	}{
		{"missing issuer", func(c jwt.MapClaims) { delete(c, "iss") }, nil},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "wrong" }, nil},
		{"missing audience", func(c jwt.MapClaims) { delete(c, "aud") }, nil},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "wrong" }, nil},
		{"missing typ", func(c jwt.MapClaims) { delete(c, "typ") }, nil},
		{"id token typ", func(c jwt.MapClaims) { c["typ"] = "ID" }, nil},
		{"refresh token typ", func(c jwt.MapClaims) { c["typ"] = "Refresh" }, nil},
		{"missing exp", func(c jwt.MapClaims) { delete(c, "exp") }, nil},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, nil},
		{"future nbf", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Minute).Unix() }, nil},
		{"missing iat", func(c jwt.MapClaims) { delete(c, "iat") }, nil},
		{"future iat", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Minute).Unix() }, nil},
		{"wrong exp type", func(c jwt.MapClaims) { c["exp"] = "tomorrow" }, nil},
		{"bad groups type", func(c jwt.MapClaims) { c["groups"] = "admin" }, nil},
		{"user injection", func(c jwt.MapClaims) { c["preferred_username"] = "a\r\nX-Admin: true" }, nil},
		{"user surrounding space", func(c jwt.MapClaims) { c["preferred_username"] = " alice " }, nil},
		{"email injection", func(c jwt.MapClaims) { c["email"] = "a\nb" }, nil},
		{"group injection", func(c jwt.MapClaims) { c["groups"] = []string{"a\rb"} }, nil},
		{"role injection", func(c jwt.MapClaims) { c["realm_access"] = map[string]any{"roles": []string{"a\nb"}} }, nil},
		{"role surrounding space", func(c jwt.MapClaims) { c["realm_access"] = map[string]any{"roles": []string{" admin "}} }, nil},
		{"empty user and subject", func(c jwt.MapClaims) { delete(c, "preferred_username"); delete(c, "sub") }, nil},
		{"whitespace user and empty sub", func(c jwt.MapClaims) { c["preferred_username"] = "   "; delete(c, "sub") }, nil},
		{"no kid", nil, map[string]any{"kid": nil}},
		{"critical extension", nil, map[string]any{"crit": []string{"example"}}},
		{"b64 extension", nil, map[string]any{"b64": true}},
		{"jku header", nil, map[string]any{"jku": "https://evil.test/jwks.json"}},
		{"x5u header", nil, map[string]any{"x5u": "https://evil.test/cert.pem"}},
		{"jwk header", nil, map[string]any{"jwk": map[string]any{"kty": "RSA"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validClaims()
			if tc.mutate != nil {
				tc.mutate(c)
			}
			_, err := v.Verify(context.Background(), signed(t, jwt.SigningMethodES256, key, c, tc.header))
			if err == nil || errors.Is(err, ErrForbidden) {
				t.Fatalf("expected authentication failure, got %v", err)
			}
		})
	}
	token := signed(t, jwt.SigningMethodES256, key, validClaims(), nil)
	for _, bad := range []string{"", token[7:], "Basic " + token[7:], "Bearer  " + token[7:], token + "\r\n", token + " ", "******"} {
		if _, err := v.Verify(context.Background(), bad); err == nil {
			t.Errorf("accepted invalid authorization %q", bad)
		}
	}
}

func TestAuthorizationAndKeyValidation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := signed(t, jwt.SigningMethodES256, key, validClaims(), nil)
	for _, tc := range []struct{ realm, client []string }{
		{[]string{"writer"}, nil}, {nil, []string{"reader"}}, {nil, []string{"other-role"}}, {[]string{"reader", "missing"}, nil},
	} {
		if _, err := verifier(t, &key.PublicKey, 0, tc.realm, tc.client).Verify(context.Background(), token); !errors.Is(err, ErrForbidden) {
			t.Fatalf("expected forbidden for %#v, got %v", tc, err)
		}
	}
	for _, invalid := range []any{nil, "secret", &rsa.PublicKey{}, &ecdsa.PublicKey{}, &ecdsa.PublicKey{Curve: elliptic.P256()}, key} {
		if _, err := verifier(t, invalid, 0, nil, nil).Verify(context.Background(), token); err == nil || errors.Is(err, ErrForbidden) {
			t.Fatalf("accepted invalid key %T: %v", invalid, err)
		}
	}
	secret := "sensitive-key-source-error"
	v, err := New(testKeys{err: errors.New(secret)}, "issuer", "audience", 0, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), token)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), token) {
		t.Fatalf("key-source error leaked: %v", err)
	}
	hmac := signed(t, jwt.SigningMethodHS256, []byte("secret"), validClaims(), nil)
	if _, err := verifier(t, []byte("secret"), 0, nil, nil).Verify(context.Background(), hmac); err == nil {
		t.Fatal("accepted HS256")
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier(t, &other.PublicKey, 0, []string{"missing"}, nil).Verify(context.Background(), token); err == nil || errors.Is(err, ErrForbidden) {
		t.Fatalf("invalid signature must fail authentication, got %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier(t, &p384.PublicKey, 0, nil, nil).Verify(context.Background(), token); err == nil {
		t.Fatal("accepted P-384 key for ES256")
	}
}

func TestSubjectFallbackAndClientIsolation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := validClaims()
	delete(c, "preferred_username")
	c["resource_access"] = map[string]any{"": map[string]any{"roles": []string{"unexpected"}}}
	token := signed(t, jwt.SigningMethodES256, key, c, nil)
	v, err := New(testKeys{key: &key.PublicKey}, "issuer", "audience", 0, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := v.Verify(context.Background(), token)
	if err != nil || identity.User != "subject" || !reflect.DeepEqual(identity.Roles, []string{"reader", "shared"}) {
		t.Fatalf("unexpected identity %#v: %v", identity, err)
	}
}

func TestSkewAndConfiguration(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := validClaims()
	c["nbf"], c["iat"], c["exp"] = time.Now().Add(10*time.Second).Unix(), time.Now().Add(10*time.Second).Unix(), time.Now().Add(-10*time.Second).Unix()
	token := signed(t, jwt.SigningMethodES256, key, c, nil)
	if _, err := verifier(t, &key.PublicKey, 30*time.Second, nil, nil).Verify(context.Background(), token); err != nil {
		t.Fatalf("valid skew rejected: %v", err)
	}
	if _, err := verifier(t, &key.PublicKey, 0, nil, nil).Verify(context.Background(), token); err == nil {
		t.Fatal("accepted invalid times without skew")
	}
	for _, tc := range []struct {
		keys             KeySource
		issuer, audience string
		skew             time.Duration
		clientRoles      []string
		clientID         string
	}{
		{nil, "issuer", "audience", 0, nil, ""},
		{testKeys{}, "", "audience", 0, nil, ""},
		{testKeys{}, "issuer", "", 0, nil, ""},
		{testKeys{}, "issuer", "audience", -1, nil, ""},
		{testKeys{}, "issuer", "audience", 31 * time.Second, nil, ""},
		{testKeys{}, "issuer", "audience", 0, []string{"role"}, ""},
		{testKeys{}, "issuer", "audience", 0, []string{""}, "app"},
	} {
		if _, err := New(tc.keys, tc.issuer, tc.audience, tc.skew, nil, tc.clientRoles, tc.clientID); err == nil {
			t.Errorf("accepted invalid configuration %#v", tc)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("ES256", func(b *testing.B) {
		v := verifier(b, &ecKey.PublicKey, 0, []string{"reader"}, []string{"writer"})
		token := signed(b, jwt.SigningMethodES256, ecKey, validClaims(), nil)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if _, err := v.Verify(context.Background(), token); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("RS256", func(b *testing.B) {
		v := verifier(b, &rsaKey.PublicKey, 0, []string{"reader"}, []string{"writer"})
		token := signed(b, jwt.SigningMethodRS256, rsaKey, validClaims(), nil)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if _, err := v.Verify(context.Background(), token); err != nil {
				b.Fatal(err)
			}
		}
	})
}

type introspectFunc func(context.Context, string) (bool, error)

func (f introspectFunc) Active(ctx context.Context, raw string) (bool, error) { return f(ctx, raw) }

func TestExtendedAuthorizationAndAlgorithms(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// EdDSA + full claim policies + custom claim header + active introspection.
	v, err := NewWithOptions(testKeys{key: edPub}, Options{
		Issuer:               "issuer",
		Audience:             "audience",
		AllowedAlgorithms:    []string{"EdDSA"},
		RequiredRealmRoles:   []string{"missing", "reader"},
		RequireAnyRole:       true,
		RequiredGroups:       []string{"two"},
		RequiredScopes:       []string{"openid", "api:read"},
		RequiredACR:          []string{"2", "3"},
		RequireEmailVerified: true,
		RequiredAZP:          "app",
		RequiredOrganization: "acme",
		CustomClaimHeaders:   map[string]string{"X-Tenant-ID": "tenant_id"},
		Introspector:         introspectFunc(func(context.Context, string) (bool, error) { return true, nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := signed(t, jwt.SigningMethodEdDSA, edPriv, validClaims(), nil)
	id, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("EdDSA verify failed: %v", err)
	}
	if id.Extra["X-Tenant-ID"] != "tenant-42" {
		t.Fatalf("expected X-Tenant-ID=tenant-42, got %#v", id.Extra)
	}

	// Inactive introspection fails closed as 401 (not ErrForbidden).
	vInactive, err := NewWithOptions(testKeys{key: edPub}, Options{
		Issuer:            "issuer",
		Audience:          "audience",
		AllowedAlgorithms: []string{"EdDSA"},
		Introspector:      introspectFunc(func(context.Context, string) (bool, error) { return false, nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vInactive.Verify(context.Background(), tok); err == nil || errors.Is(err, ErrForbidden) {
		t.Fatalf("expected 401 for inactive token, got %v", err)
	}

	// Failing claim policies return ErrForbidden.
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"missing group", Options{RequiredGroups: []string{"admins"}}},
		{"missing scope", Options{RequiredScopes: []string{"api:write"}}},
		{"wrong acr", Options{RequiredACR: []string{"3"}}},
		{"missing amr", Options{RequiredAMR: []string{"mfa"}}},
		{"wrong azp", Options{RequiredAZP: "other-client"}},
		{"wrong org", Options{RequiredOrganization: "other-org"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Issuer = "issuer"
			tc.opts.Audience = "audience"
			tc.opts.AllowedAlgorithms = []string{"ES384"}
			ver, err := NewWithOptions(testKeys{key: &ec384.PublicKey}, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			es384Tok := signed(t, jwt.SigningMethodES384, ec384, validClaims(), nil)
			if _, err := ver.Verify(context.Background(), es384Tok); !errors.Is(err, ErrForbidden) {
				t.Fatalf("expected ErrForbidden for %s, got %v", tc.name, err)
			}
		})
	}

	// Unsupported algorithm rejected at construction time.
	if _, err := NewWithOptions(testKeys{key: edPub}, Options{
		Issuer: "issuer", Audience: "audience", AllowedAlgorithms: []string{"HS256"},
	}); err == nil {
		t.Fatal("accepted HS256 in AllowedAlgorithms")
	}

	// Local RBAC failure short-circuits before online introspection.
	introCalled := false
	vSkipIntro, err := NewWithOptions(testKeys{key: edPub}, Options{
		Issuer:             "issuer",
		Audience:           "audience",
		AllowedAlgorithms:  []string{"EdDSA"},
		RequiredRealmRoles: []string{"superadmin"},
		Introspector: introspectFunc(func(context.Context, string) (bool, error) {
			introCalled = true
			return true, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vSkipIntro.Verify(context.Background(), tok); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if introCalled {
		t.Fatal("introspector should not be called when local RBAC rejects token")
	}
}

func BenchmarkVerifyEdDSA(b *testing.B) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	v, err := NewWithOptions(testKeys{key: edPub}, Options{
		Issuer:             "issuer",
		Audience:           "audience",
		AllowedAlgorithms:  []string{"EdDSA"},
		RequiredRealmRoles: []string{"reader"},
		CustomClaimHeaders: map[string]string{"X-Tenant-ID": "tenant_id"},
	})
	if err != nil {
		b.Fatal(err)
	}
	token := signed(b, jwt.SigningMethodEdDSA, edPriv, validClaims(), nil)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := v.Verify(context.Background(), token); err != nil {
			b.Fatal(err)
		}
	}
}
