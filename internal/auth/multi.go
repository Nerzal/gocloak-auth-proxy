package auth

import (
	"context"
	"errors"
	"io"
	"strings"
)

// reasonError attaches a safe, static diagnostic reason code to an auth error
// without ever changing the public Error() string or leaking token/claim values.
type reasonError struct {
	base   error
	reason string
}

func (e reasonError) Error() string { return e.base.Error() }
func (e reasonError) Unwrap() error { return e.base }

func invalidWith(reason string) error {
	return reasonError{base: errInvalid, reason: reason}
}

func forbiddenWith(reason string) error {
	return reasonError{base: ErrForbidden, reason: reason}
}

// Reason returns a safe, static machine-readable rejection reason code for an
// authentication or authorization error, suitable for debug logging without
// exposing any token, claim, or secret contents.
func Reason(err error) string {
	var re reasonError
	if errors.As(err, &re) {
		return re.reason
	}
	if errors.Is(err, ErrForbidden) {
		return "forbidden"
	}
	if err != nil {
		return "invalid"
	}
	return ""
}

// MultiVerifier dispatches bearer tokens across an explicit allowlist of
// Keycloak realm issuers, each backed by its own Verifier and JWKS cache.
type MultiVerifier struct {
	byIssuer map[string]*Verifier
}

// NewMultiVerifier constructs a multi-issuer verifier from an explicit issuer->Verifier map.
func NewMultiVerifier(verifiers map[string]*Verifier) (*MultiVerifier, error) {
	if len(verifiers) == 0 {
		return nil, errors.New("at least one issuer verifier is required")
	}
	m := make(map[string]*Verifier, len(verifiers))
	for iss, v := range verifiers {
		if strings.TrimSpace(iss) == "" || v == nil {
			return nil, errors.New("invalid issuer verifier entry")
		}
		m[iss] = v
	}
	return &MultiVerifier{byIssuer: m}, nil
}

// Verify peeks the unverified iss claim strictly via jsontext, matches it
// against the explicit issuer allowlist, and delegates full verification.
func (m *MultiVerifier) Verify(ctx context.Context, authorization string) (Identity, error) {
	scheme, raw, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(raw) == 0 || len(raw) > 65536 {
		return Identity{}, invalidWith("invalid_bearer_header")
	}
	_, payloadPart, _, _, ok := splitJWT(raw)
	if !ok {
		return Identity{}, invalidWith("malformed_jwt")
	}
	iss, ok := peekUnverifiedIssuer(payloadPart)
	if !ok || iss == "" {
		return Identity{}, invalidWith("missing_issuer")
	}
	v, allowed := m.byIssuer[iss]
	if !allowed {
		return Identity{}, invalidWith("issuer_not_allowed")
	}
	return v.Verify(ctx, authorization)
}

func peekUnverifiedIssuer(encodedPayload string) (string, bool) {
	db := getDecodeBuf()
	defer putDecodeBuf(db)
	decoded, ok := decodeBase64URL(db, encodedPayload, 65536)
	if !ok {
		return "", false
	}
	db.reader.Reset(decoded)
	db.dec.Reset(&db.reader)
	tok, err := db.dec.ReadToken()
	if err != nil || tok.Kind() != '{' {
		return "", false
	}
	for db.dec.PeekKind() != '}' {
		kTok, err := db.dec.ReadToken()
		if err != nil || kTok.Kind() != '"' {
			return "", false
		}
		if kTok.String() == "iss" {
			vTok, err := db.dec.ReadToken()
			if err != nil || vTok.Kind() != '"' {
				return "", false
			}
			return vTok.String(), true
		}
		if err := db.dec.SkipValue(); err != nil {
			return "", false
		}
	}
	if _, err := db.dec.ReadToken(); err != nil && err != io.EOF {
		return "", false
	}
	return "", false
}
