// Package auth verifies bearer tokens and extracts identities from Keycloak claims.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
)

// Identity contains the values suitable for forwarding as identity headers.
type Identity struct {
	User, Email   string
	Groups, Roles []string
}

// KeySource looks up a public verification key by key ID and JWT algorithm.
type KeySource interface {
	Key(context.Context, string, string) (any, error)
}

// ErrForbidden indicates that an authenticated identity lacks required roles.
var ErrForbidden = errors.New("insufficient permissions")

var errInvalid = errors.New("invalid authorization")

type roleClaims struct {
	Roles []string `json:"roles"`
}

type claims struct {
	jwt.RegisteredClaims
	Type           string                `json:"typ"`
	Username       string                `json:"preferred_username"`
	Email          string                `json:"email"`
	Groups         []string              `json:"groups"`
	RealmAccess    roleClaims            `json:"realm_access"`
	ResourceAccess map[string]roleClaims `json:"resource_access"`
}

// Verifier validates JWTs using a configured key source and authorization policy.
type Verifier struct {
	keys        KeySource
	parser      *jwt.Parser
	realmRoles  []string
	clientRoles []string
	clientID    string
}

// New constructs a verifier. All configured roles are required in their
// respective realm or client role set. Skew must be between zero and 30 seconds.
func New(keys KeySource, issuer, audience string, skew time.Duration, requiredRealmRoles, requiredClientRoles []string, clientID string) (*Verifier, error) {
	if keys == nil || strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" ||
		skew < 0 || skew > 30*time.Second || (len(requiredClientRoles) > 0 && strings.TrimSpace(clientID) == "") {
		return nil, errors.New("invalid verifier configuration")
	}
	for _, roles := range [][]string{requiredRealmRoles, requiredClientRoles} {
		for _, role := range roles {
			if strings.TrimSpace(role) == "" || !safeHeaderValue(role) {
				return nil, errors.New("invalid verifier configuration")
			}
		}
	}
	return &Verifier{
		keys: keys,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256", "ES256"}),
			jwt.WithIssuer(issuer), jwt.WithAudience(audience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(), jwt.WithLeeway(skew), jwt.WithStrictDecoding(),
		),
		realmRoles:  append([]string(nil), requiredRealmRoles...),
		clientRoles: append([]string(nil), requiredClientRoles...),
		clientID:    clientID,
	}, nil
}

// Verify authenticates a bearer token, then enforces the configured role policy.
// Errors do not include token, claim, or key-source contents.
func (v *Verifier) Verify(ctx context.Context, authorization string) (Identity, error) {
	scheme, raw, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(raw) == 0 || len(raw) > 65536 {
		return Identity{}, errInvalid
	}
	for _, c := range raw {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return Identity{}, errInvalid
		}
	}

	var c claims
	token, err := v.parser.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		return v.key(ctx, t)
	})
	if err != nil || token == nil || !token.Valid || c.IssuedAt == nil || c.Type != "Bearer" {
		return Identity{}, errInvalid
	}
	return v.identity(c)
}

func (v *Verifier) key(ctx context.Context, t *jwt.Token) (any, error) {
	kid, ok := t.Header["kid"].(string)
	if !ok || kid == "" || len(kid) > 256 || !safeHeaderValue(kid) {
		return nil, errInvalid
	}
	// No critical or unencoded-payload extensions are supported.
	if _, ok := t.Header["crit"]; ok {
		return nil, errInvalid
	}
	if _, ok := t.Header["b64"]; ok {
		return nil, errInvalid
	}
	alg := t.Method.Alg()
	key, err := v.keys.Key(ctx, kid, alg)
	if err != nil {
		return nil, errInvalid
	}
	switch alg {
	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok || k == nil || k.N == nil || k.N.Sign() <= 0 || k.E < 3 || k.E%2 == 0 {
			return nil, errInvalid
		}
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		//nolint:staticcheck // Guard against nil coordinates that panic inside crypto/ecdsa.Verify.
		if !ok || k == nil || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil {
			return nil, errInvalid
		}
	default:
		return nil, errInvalid
	}
	return key, nil
}

func (v *Verifier) identity(c claims) (Identity, error) {
	user := c.Username
	if user == "" {
		user = c.Subject
	}
	if strings.TrimSpace(user) == "" {
		return Identity{}, errInvalid
	}
	var client []string
	if v.clientID != "" {
		client = c.ResourceAccess[v.clientID].Roles
	}
	roles := uniqueRoles(c.RealmAccess.Roles, client)
	if !safeHeaderValue(user) || !safeHeaderValue(c.Email) || !safeValues(c.Groups) || !safeValues(roles) {
		return Identity{}, errInvalid
	}
	if !hasRoles(c.RealmAccess.Roles, v.realmRoles) || !hasRoles(client, v.clientRoles) {
		return Identity{}, ErrForbidden
	}
	return Identity{User: user, Email: c.Email, Groups: c.Groups, Roles: roles}, nil
}

func safeHeaderValue(s string) bool {
	if strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func safeValues(values []string) bool {
	for _, value := range values {
		if value == "" || !safeHeaderValue(value) {
			return false
		}
	}
	return true
}

func hasRoles(actual, required []string) bool {
	if len(required) == 0 {
		return true
	}
	if len(actual) <= 16 || len(required) <= 4 {
		for _, role := range required {
			if !slices.Contains(actual, role) {
				return false
			}
		}
		return true
	}
	set := make(map[string]struct{}, len(actual))
	for _, role := range actual {
		set[role] = struct{}{}
	}
	for _, role := range required {
		if _, ok := set[role]; !ok {
			return false
		}
	}
	return true
}

func uniqueRoles(realm, client []string) []string {
	total := len(realm) + len(client)
	if total == 0 {
		return nil
	}
	roles := make([]string, 0, total)
	if total <= 8 {
		for _, role := range realm {
			if !slices.Contains(roles, role) {
				roles = append(roles, role)
			}
		}
		for _, role := range client {
			if !slices.Contains(roles, role) {
				roles = append(roles, role)
			}
		}
		return roles
	}
	seen := make(map[string]struct{}, total)
	for _, group := range [2][]string{realm, client} {
		for _, role := range group {
			if _, ok := seen[role]; !ok {
				seen[role] = struct{}{}
				roles = append(roles, role)
			}
		}
	}
	return roles
}
