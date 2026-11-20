// Package auth verifies bearer tokens and extracts identities from Keycloak claims.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
)

// Identity contains the values suitable for forwarding as identity headers.
type Identity struct {
	User, Email   string
	Groups, Roles []string
	RealmRoles    []string
	ClientRoles   []string
	Extra         map[string]string
	RawToken      string
}

// KeySource looks up a public verification key by key ID and JWT algorithm.
type KeySource interface {
	Key(context.Context, string, string) (any, error)
}

// TokenIntrospector verifies online whether a token is still active.
type TokenIntrospector interface {
	Active(ctx context.Context, rawToken string) (bool, error)
}

// ErrForbidden indicates that an authenticated identity lacks required roles or claims.
var ErrForbidden = errors.New("insufficient permissions")

var errInvalid = errors.New("invalid authorization")

type roleClaims struct {
	Roles []string `json:"roles"`
}

// orgClaim handles Keycloak 26+ organization claims whether encoded as a string,
// string slice, or object map keyed by organization alias.
type orgClaim []string

func (o *orgClaim) UnmarshalJSON(data []byte) error {
	i := 0
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n') {
		i++
	}
	if i == len(data) {
		return nil
	}
	switch data[i] {
	case 'n':
		if string(data[i:]) == "null" {
			return nil
		}
	case '"':
		var single string
		if err := json.Unmarshal(data[i:], &single); err != nil {
			return err
		}
		if single != "" {
			*o = []string{single}
		}
		return nil
	case '[':
		var list []string
		if err := json.Unmarshal(data[i:], &list); err != nil {
			return err
		}
		*o = list
		return nil
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data[i:], &obj); err != nil {
			return err
		}
		names := make([]string, 0, len(obj))
		for k := range obj {
			names = append(names, k)
		}
		*o = names
		return nil
	}
	return errors.New("invalid organization claim")
}

type claims struct {
	jwt.RegisteredClaims
	Type           string                `json:"typ"`
	Username       string                `json:"preferred_username"`
	Email          string                `json:"email"`
	EmailVerified  bool                  `json:"email_verified"`
	AZP            string                `json:"azp"`
	Scope          string                `json:"scope"`
	ACR            string                `json:"acr"`
	Organization   orgClaim              `json:"organization"`
	Groups         []string              `json:"groups"`
	RealmAccess    roleClaims            `json:"realm_access"`
	ResourceAccess map[string]roleClaims `json:"resource_access"`
}

// Options configures JWT verification and authorization policies.
type Options struct {
	Issuer               string
	Audience             string
	ClockSkew            time.Duration
	AllowedAlgorithms    []string
	RequiredRealmRoles   []string
	RequiredClientRoles  []string
	ClientID             string
	RequireAnyRole       bool
	RequiredGroups       []string
	RequireAnyGroup      bool
	RequiredScopes       []string
	RequiredACR          []string
	RequireEmailVerified bool
	RequiredAZP          string
	RequiredOrganization string
	CustomClaimHeaders   map[string]string
	Introspector         TokenIntrospector
}

// Verifier validates JWTs using a configured key source and authorization policy.
type Verifier struct {
	keys                 KeySource
	parser               *jwt.Parser
	realmRoles           []string
	clientRoles          []string
	clientID             string
	requireAnyRole       bool
	requiredGroups       []string
	requireAnyGroup      bool
	requiredScopes       []string
	requiredACR          []string
	requireEmailVerified bool
	requiredAZP          string
	requiredOrg          string
	customClaims         map[string]string
	introspector         TokenIntrospector
}

func isAllowedAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		return true
	}
	return false
}

// New constructs a verifier with default asymmetric algorithms (RS256, ES256).
// All configured roles are required in their respective realm or client role
// set. Skew must be between zero and 30 seconds.
func New(keys KeySource, issuer, audience string, skew time.Duration, requiredRealmRoles, requiredClientRoles []string, clientID string) (*Verifier, error) {
	return NewWithOptions(keys, Options{
		Issuer:              issuer,
		Audience:            audience,
		ClockSkew:           skew,
		RequiredRealmRoles:  requiredRealmRoles,
		RequiredClientRoles: requiredClientRoles,
		ClientID:            clientID,
	})
}

// NewWithOptions constructs a verifier with full authorization and claim policies.
func NewWithOptions(keys KeySource, opts Options) (*Verifier, error) {
	if keys == nil || strings.TrimSpace(opts.Issuer) == "" || strings.TrimSpace(opts.Audience) == "" ||
		opts.ClockSkew < 0 || opts.ClockSkew > 30*time.Second ||
		(len(opts.RequiredClientRoles) > 0 && strings.TrimSpace(opts.ClientID) == "") {
		return nil, errors.New("invalid verifier configuration")
	}
	algs := opts.AllowedAlgorithms
	if len(algs) == 0 {
		algs = []string{"RS256", "ES256"}
	} else {
		algs = append([]string(nil), algs...)
		for _, alg := range algs {
			if !isAllowedAlgorithm(alg) {
				return nil, fmt.Errorf("unsupported signing algorithm %q", alg)
			}
		}
	}
	for _, list := range [][]string{opts.RequiredRealmRoles, opts.RequiredClientRoles, opts.RequiredGroups, opts.RequiredScopes, opts.RequiredACR} {
		for _, item := range list {
			if strings.TrimSpace(item) == "" || !safeHeaderValue(item) {
				return nil, errors.New("invalid verifier configuration")
			}
		}
	}
	var custom map[string]string
	if len(opts.CustomClaimHeaders) > 0 {
		custom = make(map[string]string, len(opts.CustomClaimHeaders))
		for header, claim := range opts.CustomClaimHeaders {
			if strings.TrimSpace(header) == "" || strings.TrimSpace(claim) == "" {
				return nil, errors.New("invalid custom claim header mapping")
			}
			custom[header] = claim
		}
	}
	return &Verifier{
		keys: keys,
		parser: jwt.NewParser(
			jwt.WithValidMethods(algs),
			jwt.WithIssuer(opts.Issuer), jwt.WithAudience(opts.Audience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(), jwt.WithLeeway(opts.ClockSkew), jwt.WithStrictDecoding(),
		),
		realmRoles:           append([]string(nil), opts.RequiredRealmRoles...),
		clientRoles:          append([]string(nil), opts.RequiredClientRoles...),
		clientID:             opts.ClientID,
		requireAnyRole:       opts.RequireAnyRole,
		requiredGroups:       append([]string(nil), opts.RequiredGroups...),
		requireAnyGroup:      opts.RequireAnyGroup,
		requiredScopes:       append([]string(nil), opts.RequiredScopes...),
		requiredACR:          append([]string(nil), opts.RequiredACR...),
		requireEmailVerified: opts.RequireEmailVerified,
		requiredAZP:          opts.RequiredAZP,
		requiredOrg:          opts.RequiredOrganization,
		customClaims:         custom,
		introspector:         opts.Introspector,
	}, nil
}

// Verify authenticates a bearer token, then enforces the configured role and
// claim policy. Errors do not include token, claim, or key-source contents.
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
	id, err := v.identity(c, raw)
	if err != nil {
		return Identity{}, err
	}
	if v.introspector != nil {
		active, err := v.introspector.Active(ctx, raw)
		if err != nil || !active {
			return Identity{}, errInvalid
		}
	}
	return id, nil
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
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
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
	case "ES384":
		k, ok := key.(*ecdsa.PublicKey)
		//nolint:staticcheck // Guard against nil coordinates that panic inside crypto/ecdsa.Verify.
		if !ok || k == nil || k.Curve != elliptic.P384() || k.X == nil || k.Y == nil {
			return nil, errInvalid
		}
	case "ES512":
		k, ok := key.(*ecdsa.PublicKey)
		//nolint:staticcheck // Guard against nil coordinates that panic inside crypto/ecdsa.Verify.
		if !ok || k == nil || k.Curve != elliptic.P521() || k.X == nil || k.Y == nil {
			return nil, errInvalid
		}
	case "EdDSA":
		k, ok := key.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return nil, errInvalid
		}
	default:
		return nil, errInvalid
	}
	return key, nil
}

func (v *Verifier) identity(c claims, raw string) (Identity, error) {
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
	if !v.authorize(c, client) {
		return Identity{}, ErrForbidden
	}
	var extra map[string]string
	if len(v.customClaims) > 0 {
		var err error
		extra, err = extractCustomClaims(raw, v.customClaims)
		if err != nil {
			return Identity{}, errInvalid
		}
	}
	return Identity{
		User:        user,
		Email:       c.Email,
		Groups:      c.Groups,
		Roles:       roles,
		RealmRoles:  c.RealmAccess.Roles,
		ClientRoles: client,
		Extra:       extra,
		RawToken:    raw,
	}, nil
}

func (v *Verifier) authorize(c claims, clientRoles []string) bool {
	if !matchValues(c.RealmAccess.Roles, v.realmRoles, v.requireAnyRole) {
		return false
	}
	if !matchValues(clientRoles, v.clientRoles, v.requireAnyRole) {
		return false
	}
	if !matchValues(c.Groups, v.requiredGroups, v.requireAnyGroup) {
		return false
	}
	if len(v.requiredScopes) > 0 {
		tokenScopes := strings.Fields(c.Scope)
		if !matchValues(tokenScopes, v.requiredScopes, false) {
			return false
		}
	}
	if len(v.requiredACR) > 0 && !slices.Contains(v.requiredACR, c.ACR) {
		return false
	}
	if v.requireEmailVerified && !c.EmailVerified {
		return false
	}
	if v.requiredAZP != "" && c.AZP != v.requiredAZP {
		return false
	}
	if v.requiredOrg != "" && !slices.Contains([]string(c.Organization), v.requiredOrg) {
		return false
	}
	return true
}

func extractCustomClaims(raw string, mapping map[string]string) (map[string]string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errInvalid
	}
	var rawClaims map[string]any
	if err := json.Unmarshal(payload, &rawClaims); err != nil {
		return nil, errInvalid
	}
	extra := make(map[string]string, len(mapping))
	for header, claimKey := range mapping {
		val, ok := rawClaims[claimKey]
		if !ok || val == nil {
			continue
		}
		str, ok := stringifyClaim(val)
		if !ok || !safeHeaderValue(str) {
			return nil, errInvalid
		}
		extra[header] = str
	}
	return extra, nil
}

func stringifyClaim(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case []any:
		parts := make([]string, 0, len(t))
		for _, elem := range t {
			s, ok := elem.(string)
			if !ok || s == "" || strings.Contains(s, ",") || !safeHeaderValue(s) {
				return "", false
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ","), true
	default:
		return "", false
	}
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

func matchValues(actual, required []string, anyOf bool) bool {
	if len(required) == 0 {
		return true
	}
	if anyOf {
		for _, req := range required {
			if slices.Contains(actual, req) {
				return true
			}
		}
		return false
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
