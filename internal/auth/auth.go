// Package auth verifies bearer tokens and extracts identities from Keycloak claims.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Identity contains the values suitable for forwarding as identity headers.
type Identity struct {
	User, Email   string
	Subject, SID  string
	ACR           string
	AMR           []string
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
	RequiredAMR          []string
	RequireEmailVerified bool
	RequiredAZP          string
	RequiredOrganization string
	CustomClaimHeaders   map[string]string
	Introspector         TokenIntrospector
	// TokenCacheSize enables a bounded, SHA-256-keyed verified-token cache that
	// re-checks exp/nbf, JWKS key identity, and online introspection on every hit.
	// Zero disables caching (full cryptographic verification on every call).
	TokenCacheSize int
}

const tokenCacheShards = 16

type cachedVerification struct {
	kid      string
	alg      string
	key      any
	exp      float64
	nbf      float64
	hasNbf   bool
	identity Identity
}

type tokenCacheShard struct {
	mu      sync.RWMutex
	entries map[[32]byte]cachedVerification
}

type verifiedTokenCache struct {
	maxPerShard int
	shards      [tokenCacheShards]tokenCacheShard
}

func newVerifiedTokenCache(maxEntries int) *verifiedTokenCache {
	if maxEntries <= 0 {
		return nil
	}
	perShard := max(maxEntries/tokenCacheShards, 16)
	c := &verifiedTokenCache{maxPerShard: perShard}
	for i := range c.shards {
		c.shards[i].entries = make(map[[32]byte]cachedVerification, min(perShard, 64))
	}
	return c
}

func (c *verifiedTokenCache) get(hash [32]byte) (cachedVerification, bool) {
	shard := &c.shards[hash[0]&(tokenCacheShards-1)]
	shard.mu.RLock()
	entry, ok := shard.entries[hash]
	shard.mu.RUnlock()
	return entry, ok
}

func (c *verifiedTokenCache) set(hash [32]byte, entry cachedVerification, nowSec, skewSec float64) {
	shard := &c.shards[hash[0]&(tokenCacheShards-1)]
	shard.mu.Lock()
	if len(shard.entries) >= c.maxPerShard {
		for k, e := range shard.entries {
			if nowSec > e.exp+skewSec {
				delete(shard.entries, k)
			}
		}
		if len(shard.entries) >= c.maxPerShard {
			shard.entries = make(map[[32]byte]cachedVerification, min(c.maxPerShard, 64))
		}
	}
	shard.entries[hash] = entry
	shard.mu.Unlock()
}

// Verifier validates JWTs using a configured key source and authorization policy.
type Verifier struct {
	keys                 KeySource
	issuer               string
	audience             string
	skewSec              float64
	allowedAlgs          []string
	realmRoles           []string
	clientRoles          []string
	clientID             string
	requireAnyRole       bool
	requiredGroups       []string
	requireAnyGroup      bool
	requiredScopes       []string
	requiredACR          []string
	requiredAMR          []string
	requireEmailVerified bool
	requiredAZP          string
	requiredOrg          string
	customByClaim        map[string][]string
	introspector         TokenIntrospector
	tokenCache           *verifiedTokenCache
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
	for _, list := range [][]string{opts.RequiredRealmRoles, opts.RequiredClientRoles, opts.RequiredGroups, opts.RequiredScopes, opts.RequiredACR, opts.RequiredAMR} {
		for _, item := range list {
			if strings.TrimSpace(item) == "" || !safeHeaderValue(item) {
				return nil, errors.New("invalid verifier configuration")
			}
		}
	}
	var customByClaim map[string][]string
	if len(opts.CustomClaimHeaders) > 0 {
		customByClaim = make(map[string][]string, len(opts.CustomClaimHeaders))
		for header, claim := range opts.CustomClaimHeaders {
			if strings.TrimSpace(header) == "" || strings.TrimSpace(claim) == "" {
				return nil, errors.New("invalid custom claim header mapping")
			}
			customByClaim[claim] = append(customByClaim[claim], header)
		}
	}
	return &Verifier{
		keys:                 keys,
		issuer:               opts.Issuer,
		audience:             opts.Audience,
		skewSec:              opts.ClockSkew.Seconds(),
		allowedAlgs:          algs,
		realmRoles:           append([]string(nil), opts.RequiredRealmRoles...),
		clientRoles:          append([]string(nil), opts.RequiredClientRoles...),
		clientID:             opts.ClientID,
		requireAnyRole:       opts.RequireAnyRole,
		requiredGroups:       append([]string(nil), opts.RequiredGroups...),
		requireAnyGroup:      opts.RequireAnyGroup,
		requiredScopes:       append([]string(nil), opts.RequiredScopes...),
		requiredACR:          append([]string(nil), opts.RequiredACR...),
		requiredAMR:          append([]string(nil), opts.RequiredAMR...),
		requireEmailVerified: opts.RequireEmailVerified,
		requiredAZP:          opts.RequiredAZP,
		requiredOrg:          opts.RequiredOrganization,
		customByClaim:        customByClaim,
		introspector:         opts.Introspector,
		tokenCache:           newVerifiedTokenCache(opts.TokenCacheSize),
	}, nil
}

// Verify authenticates a bearer token, then enforces the configured role and
// claim policy. Errors do not include token, claim, or key-source contents.
func (v *Verifier) Verify(ctx context.Context, authorization string) (Identity, error) {
	scheme, raw, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(raw) == 0 || len(raw) > 65536 {
		return Identity{}, errInvalid
	}

	var tokenHash [32]byte
	if v.tokenCache != nil {
		tokenHash = sha256String(raw)
		if entry, hit := v.tokenCache.get(tokenHash); hit {
			nowSec := float64(time.Now().UnixNano()) / 1e9
			if nowSec <= entry.exp+v.skewSec && (!entry.hasNbf || nowSec+v.skewSec >= entry.nbf) {
				if curKey, err := v.keys.Key(ctx, entry.kid, entry.alg); err == nil && samePublicKey(curKey, entry.key) {
					if v.introspector != nil {
						active, err := v.introspector.Active(ctx, raw)
						if err != nil || !active {
							return Identity{}, errInvalid
						}
					}
					return entry.identity, nil
				}
			}
		}
	}

	hdrPart, payloadPart, sigPart, signingInput, ok := splitJWT(raw)
	if !ok {
		return Identity{}, errInvalid
	}

	db := getDecodeBuf()
	defer putDecodeBuf(db)

	alg, kid, err := parseJWSHeader(db, hdrPart)
	if err != nil || !slices.Contains(v.allowedAlgs, alg) || kid == "" || len(kid) > 256 || !safeHeaderValue(kid) {
		return Identity{}, errInvalid
	}

	key, err := v.keys.Key(ctx, kid, alg)
	if err != nil || !validPublicKey(alg, key) {
		return Identity{}, errInvalid
	}

	if err := verifyJWSSignature(alg, key, signingInput, sigPart, db); err != nil {
		return Identity{}, errInvalid
	}

	c, err := parseJWTPayload(db, payloadPart, v.clientID, v.customByClaim)
	if err != nil {
		return Identity{}, errInvalid
	}
	if len(v.customByClaim) > 0 {
		if err := populateStandardCustomClaims(&c, v.customByClaim); err != nil {
			return Identity{}, errInvalid
		}
	}

	nowSec := float64(time.Now().UnixNano()) / 1e9
	if !v.validRegisteredClaims(c, nowSec) {
		return Identity{}, errInvalid
	}

	id, err := v.identity(c, raw)
	if err != nil {
		return Identity{}, err
	}

	if v.tokenCache != nil {
		v.tokenCache.set(tokenHash, cachedVerification{
			kid:      kid,
			alg:      alg,
			key:      key,
			exp:      c.exp,
			nbf:      c.nbf,
			hasNbf:   c.hasNbf,
			identity: id,
		}, nowSec, v.skewSec)
	}

	if v.introspector != nil {
		active, err := v.introspector.Active(ctx, raw)
		if err != nil || !active {
			return Identity{}, errInvalid
		}
	}
	return id, nil
}

func (v *Verifier) validRegisteredClaims(c parsedClaims, nowSec float64) bool {
	if c.typ != "Bearer" || c.issuer != v.issuer || !slices.Contains(c.audience, v.audience) {
		return false
	}
	if !c.hasExp || !c.hasIat {
		return false
	}
	if nowSec > c.exp+v.skewSec {
		return false
	}
	if c.iat > nowSec+v.skewSec {
		return false
	}
	if c.hasNbf && c.nbf > nowSec+v.skewSec {
		return false
	}
	return true
}

func validPublicKey(alg string, key any) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		k, ok := key.(*rsa.PublicKey)
		return ok && k != nil && k.N != nil && k.N.Sign() > 0 && k.E >= 3 && k.E%2 != 0
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		//nolint:staticcheck // Guard against nil coordinates that panic inside crypto/ecdsa.Verify.
		return ok && k != nil && k.Curve == elliptic.P256() && k.X != nil && k.Y != nil
	case "ES384":
		k, ok := key.(*ecdsa.PublicKey)
		//nolint:staticcheck // Guard against nil coordinates that panic inside crypto/ecdsa.Verify.
		return ok && k != nil && k.Curve == elliptic.P384() && k.X != nil && k.Y != nil
	case "ES512":
		k, ok := key.(*ecdsa.PublicKey)
		//nolint:staticcheck // Guard against nil coordinates that panic inside crypto/ecdsa.Verify.
		return ok && k != nil && k.Curve == elliptic.P521() && k.X != nil && k.Y != nil
	case "EdDSA":
		k, ok := key.(ed25519.PublicKey)
		return ok && len(k) == ed25519.PublicKeySize
	default:
		return false
	}
}

func samePublicKey(a, b any) bool {
	switch ka := a.(type) {
	case *rsa.PublicKey:
		kb, ok := b.(*rsa.PublicKey)
		return ok && ka == kb
	case *ecdsa.PublicKey:
		kb, ok := b.(*ecdsa.PublicKey)
		return ok && ka == kb
	case ed25519.PublicKey:
		kb, ok := b.(ed25519.PublicKey)
		return ok && ka.Equal(kb)
	default:
		return false
	}
}

func populateStandardCustomClaims(c *parsedClaims, customByClaim map[string][]string) error {
	for claimKey, headers := range customByClaim {
		var val string
		var matched bool
		switch claimKey {
		case "iss":
			val, matched = c.issuer, c.issuer != ""
		case "sub":
			val, matched = c.subject, c.subject != ""
		case "sid":
			val, matched = c.sid, c.sid != ""
		case "preferred_username":
			val, matched = c.username, c.username != ""
		case "email":
			val, matched = c.email, c.email != ""
		case "email_verified":
			val, matched = strconv.FormatBool(c.emailVerified), true
		case "azp":
			val, matched = c.azp, c.azp != ""
		case "scope":
			val, matched = c.scope, c.scope != ""
		case "acr":
			val, matched = c.acr, c.acr != ""
		default:
			continue
		}
		if !matched {
			continue
		}
		if !safeHeaderValue(val) {
			return errInvalid
		}
		if c.extra == nil {
			c.extra = make(map[string]string, len(customByClaim))
		}
		for _, h := range headers {
			c.extra[h] = val
		}
	}
	return nil
}

func (v *Verifier) identity(c parsedClaims, raw string) (Identity, error) {
	user := c.username
	if user == "" {
		user = c.subject
	}
	if strings.TrimSpace(user) == "" {
		return Identity{}, errInvalid
	}
	roles := uniqueRoles(c.realmRoles, c.clientRoles)
	if !safeHeaderValue(user) || !safeHeaderValue(c.email) || !safeValues(c.groups) || !safeValues(roles) {
		return Identity{}, errInvalid
	}
	if !v.authorize(c) {
		return Identity{}, ErrForbidden
	}
	return Identity{
		User:        user,
		Email:       c.email,
		Subject:     c.subject,
		SID:         c.sid,
		ACR:         c.acr,
		AMR:         c.amr,
		Groups:      c.groups,
		Roles:       roles,
		RealmRoles:  c.realmRoles,
		ClientRoles: c.clientRoles,
		Extra:       c.extra,
		RawToken:    raw,
	}, nil
}

func (v *Verifier) authorize(c parsedClaims) bool {
	if !matchValues(c.realmRoles, v.realmRoles, v.requireAnyRole) {
		return false
	}
	if !matchValues(c.clientRoles, v.clientRoles, v.requireAnyRole) {
		return false
	}
	if !matchValues(c.groups, v.requiredGroups, v.requireAnyGroup) {
		return false
	}
	if len(v.requiredScopes) > 0 {
		tokenScopes := strings.Fields(c.scope)
		if !matchValues(tokenScopes, v.requiredScopes, false) {
			return false
		}
	}
	if len(v.requiredACR) > 0 && !slices.Contains(v.requiredACR, c.acr) {
		return false
	}
	if len(v.requiredAMR) > 0 && !matchValues(c.amr, v.requiredAMR, false) {
		return false
	}
	if v.requireEmailVerified && !c.emailVerified {
		return false
	}
	if v.requiredAZP != "" && c.azp != v.requiredAZP {
		return false
	}
	if v.requiredOrg != "" && !slices.Contains(c.organization, v.requiredOrg) {
		return false
	}
	return true
}

func safeHeaderValue(s string) bool {
	if len(s) == 0 {
		return true
	}
	if s[0] <= ' ' || s[len(s)-1] <= ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f {
			return false
		}
		if b >= 0x80 {
			if strings.TrimSpace(s) != s {
				return false
			}
			for _, r := range s[i:] {
				if unicode.IsControl(r) {
					return false
				}
			}
			return true
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
	if len(client) == 0 {
		// Fast path: check if realm roles are already unique without allocating.
		if len(realm) <= 1 {
			return realm
		}
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
