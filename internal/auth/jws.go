package auth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/jsontext"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
)

const (
	maxHeaderDecodedBytes = 4096
	maxSigDecodedBytes    = 1024
)

type decodeBuf struct {
	raw    []byte
	buf    []byte
	reader bytes.Reader
	dec    *jsontext.Decoder
}

var decodePool = sync.Pool{
	New: func() any {
		db := &decodeBuf{
			raw: make([]byte, 0, 2048),
			buf: make([]byte, 0, 2048),
		}
		db.dec = jsontext.NewDecoder(&db.reader)
		return db
	},
}

func getDecodeBuf() *decodeBuf {
	return decodePool.Get().(*decodeBuf)
}

func putDecodeBuf(db *decodeBuf) {
	if cap(db.raw) > 65536 {
		db.raw = make([]byte, 0, 2048)
	}
	if cap(db.buf) > 65536 {
		db.buf = make([]byte, 0, 2048)
	}
	decodePool.Put(db)
}

func sha256String(s string) [32]byte {
	db := getDecodeBuf()
	db.raw = append(db.raw[:0], s...)
	sum := sha256.Sum256(db.raw)
	putDecodeBuf(db)
	return sum
}

type parsedClaims struct {
	issuer        string
	subject       string
	audience      []string
	exp           float64
	hasExp        bool
	nbf           float64
	hasNbf        bool
	iat           float64
	hasIat        bool
	typ           string
	sid           string
	username      string
	email         string
	emailVerified bool
	azp           string
	scope         string
	acr           string
	amr           []string
	organization  []string
	groups        []string
	realmRoles    []string
	clientRoles   []string
	extra         map[string]string
}

var validJWTChar = func() [256]bool {
	var t [256]bool
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	t['-'] = true
	t['_'] = true
	return t
}()

func splitJWT(raw string) (hdr, payload, sig, signingInput string, ok bool) {
	dot1, dot2 := -1, -1
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b == '.' {
			if dot1 < 0 {
				dot1 = i
			} else if dot2 < 0 {
				dot2 = i
			} else {
				return "", "", "", "", false
			}
			continue
		}
		if !validJWTChar[b] {
			return "", "", "", "", false
		}
	}
	if dot1 <= 0 || dot2 <= dot1+1 || dot2+1 >= len(raw) {
		return "", "", "", "", false
	}
	return raw[:dot1], raw[dot1+1 : dot2], raw[dot2+1:], raw[:dot2], true
}

func decodeBase64URL(db *decodeBuf, encoded string, maxDecoded int) ([]byte, bool) {
	maxLen := base64.RawURLEncoding.DecodedLen(len(encoded))
	if maxLen == 0 || maxLen > maxDecoded {
		return nil, false
	}
	db.raw = append(db.raw[:0], encoded...)
	if cap(db.buf) < maxLen {
		db.buf = make([]byte, maxLen)
	}
	n, err := base64.RawURLEncoding.Strict().Decode(db.buf[:maxLen], db.raw)
	if err != nil || n == 0 || n > maxDecoded {
		return nil, false
	}
	return db.buf[:n], true
}

func parseJWSHeader(db *decodeBuf, encodedHeader string) (alg, kid string, err error) {
	decoded, ok := decodeBase64URL(db, encodedHeader, maxHeaderDecodedBytes)
	if !ok {
		return "", "", errInvalid
	}
	db.reader.Reset(decoded)
	db.dec.Reset(&db.reader)

	tok, err := db.dec.ReadToken()
	if err != nil || tok.Kind() != '{' {
		return "", "", errInvalid
	}
	for db.dec.PeekKind() != '}' {
		kTok, err := db.dec.ReadToken()
		if err != nil || kTok.Kind() != '"' {
			return "", "", errInvalid
		}
		switch kTok.String() {
		case "alg":
			vTok, err := db.dec.ReadToken()
			if err != nil || vTok.Kind() != '"' {
				return "", "", errInvalid
			}
			alg = vTok.String()
		case "kid":
			vTok, err := db.dec.ReadToken()
			if err != nil || vTok.Kind() != '"' {
				return "", "", errInvalid
			}
			kid = vTok.String()
		case "crit", "b64", "jku", "x5u", "jwk":
			// No critical, unencoded-payload, or embedded/remote key extensions are supported.
			return "", "", errInvalid
		default:
			if err := db.dec.SkipValue(); err != nil {
				return "", "", errInvalid
			}
		}
	}
	if _, err := db.dec.ReadToken(); err != nil {
		return "", "", errInvalid
	}
	if _, err := db.dec.ReadToken(); err != io.EOF {
		return "", "", errInvalid
	}
	return alg, kid, nil
}

func verifyJWSSignature(alg string, key any, signingInput, encodedSig string, db *decodeBuf) error {
	maxSig := base64.RawURLEncoding.DecodedLen(len(encodedSig))
	if maxSig == 0 || maxSig > maxSigDecodedBytes {
		return errInvalid
	}
	var sigBuf [maxSigDecodedBytes]byte
	db.raw = append(db.raw[:0], encodedSig...)
	sigLen, err := base64.RawURLEncoding.Strict().Decode(sigBuf[:maxSig], db.raw)
	if err != nil || sigLen == 0 {
		return errInvalid
	}
	sig := sigBuf[:sigLen]

	db.raw = append(db.raw[:0], signingInput...)

	switch alg {
	case "RS256":
		h := sha256.Sum256(db.raw)
		return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, h[:], sig)
	case "RS384":
		h := sha512.Sum384(db.raw)
		return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA384, h[:], sig)
	case "RS512":
		h := sha512.Sum512(db.raw)
		return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA512, h[:], sig)
	case "PS256":
		h := sha256.Sum256(db.raw)
		return rsa.VerifyPSS(key.(*rsa.PublicKey), crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "PS384":
		h := sha512.Sum384(db.raw)
		return rsa.VerifyPSS(key.(*rsa.PublicKey), crypto.SHA384, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "PS512":
		h := sha512.Sum512(db.raw)
		return rsa.VerifyPSS(key.(*rsa.PublicKey), crypto.SHA512, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "ES256":
		h := sha256.Sum256(db.raw)
		return verifyECDSASig(key.(*ecdsa.PublicKey), h[:], sig, 32)
	case "ES384":
		h := sha512.Sum384(db.raw)
		return verifyECDSASig(key.(*ecdsa.PublicKey), h[:], sig, 48)
	case "ES512":
		h := sha512.Sum512(db.raw)
		return verifyECDSASig(key.(*ecdsa.PublicKey), h[:], sig, 66)
	case "EdDSA":
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(key.(ed25519.PublicKey), db.raw, sig) {
			return errInvalid
		}
		return nil
	default:
		return errInvalid
	}
}

func verifyECDSASig(pub *ecdsa.PublicKey, digest, sig []byte, coordSize int) error {
	if len(sig) != 2*coordSize {
		return errInvalid
	}
	var r, s big.Int
	r.SetBytes(sig[:coordSize])
	s.SetBytes(sig[coordSize:])
	if !ecdsa.Verify(pub, digest, &r, &s) {
		return errInvalid
	}
	return nil
}

func parseJWTPayload(db *decodeBuf, encodedPayload, clientID string, customByClaim map[string][]string) (parsedClaims, error) {
	decoded, ok := decodeBase64URL(db, encodedPayload, 65536)
	if !ok {
		return parsedClaims{}, errInvalid
	}
	db.reader.Reset(decoded)
	db.dec.Reset(&db.reader)

	tok, err := db.dec.ReadToken()
	if err != nil || tok.Kind() != '{' {
		return parsedClaims{}, errInvalid
	}

	var c parsedClaims
	for db.dec.PeekKind() != '}' {
		kTok, err := db.dec.ReadToken()
		if err != nil || kTok.Kind() != '"' {
			return parsedClaims{}, errInvalid
		}
		key := kTok.String()

		switch key {
		case "iss":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.issuer = s
		case "sub":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.subject = s
		case "aud":
			aud, err := readStringOrSlice(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.audience = aud
		case "exp":
			v, has, err := readOptNumber(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.exp, c.hasExp = v, has
		case "nbf":
			v, has, err := readOptNumber(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.nbf, c.hasNbf = v, has
		case "iat":
			v, has, err := readOptNumber(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.iat, c.hasIat = v, has
		case "typ":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.typ = s
		case "sid":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.sid = s
		case "preferred_username":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.username = s
		case "email":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.email = s
		case "email_verified":
			b, err := readOptBool(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.emailVerified = b
		case "azp":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.azp = s
		case "scope":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.scope = s
		case "acr":
			s, err := readOptString(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.acr = s
		case "amr":
			list, err := readOptStringSlice(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.amr = list
		case "groups":
			list, err := readOptStringSlice(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.groups = list
		case "organization":
			orgs, err := readOrgClaim(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.organization = orgs
		case "realm_access":
			roles, err := readRoleObject(db.dec)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.realmRoles = roles
		case "resource_access":
			roles, err := readResourceAccess(db.dec, clientID)
			if err != nil {
				return parsedClaims{}, errInvalid
			}
			c.clientRoles = roles
		default:
			if headers, ok := customByClaim[key]; ok {
				if db.dec.PeekKind() == 'n' {
					if _, err := db.dec.ReadToken(); err != nil {
						return parsedClaims{}, errInvalid
					}
					continue
				}
				val, ok := readCustomClaimValue(db.dec)
				if !ok || !safeHeaderValue(val) {
					return parsedClaims{}, errInvalid
				}
				if c.extra == nil {
					c.extra = make(map[string]string, len(customByClaim))
				}
				for _, h := range headers {
					c.extra[h] = val
				}
			} else {
				if err := db.dec.SkipValue(); err != nil {
					return parsedClaims{}, errInvalid
				}
			}
		}
	}
	if _, err := db.dec.ReadToken(); err != nil {
		return parsedClaims{}, errInvalid
	}
	if _, err := db.dec.ReadToken(); err != io.EOF {
		return parsedClaims{}, errInvalid
	}
	return c, nil
}

func readOptString(dec *jsontext.Decoder) (string, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return "", err
	}
	switch tok.Kind() {
	case '"':
		return tok.String(), nil
	case 'n':
		return "", nil
	default:
		return "", errInvalid
	}
}

func readOptBool(dec *jsontext.Decoder) (bool, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return false, err
	}
	switch tok.Kind() {
	case 't', 'f':
		return tok.Bool(), nil
	case 'n':
		return false, nil
	default:
		return false, errInvalid
	}
}

func readOptNumber(dec *jsontext.Decoder) (float64, bool, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return 0, false, err
	}
	switch tok.Kind() {
	case '0':
		f, err := tok.Float()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false, errInvalid
		}
		return f, true, nil
	case 'n':
		return 0, false, nil
	default:
		return 0, false, errInvalid
	}
}

func readOptStringSlice(dec *jsontext.Decoder) ([]string, error) {
	switch dec.PeekKind() {
	case 'n':
		_, err := dec.ReadToken()
		return nil, err
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var out []string
		for dec.PeekKind() != ']' {
			tok, err := dec.ReadToken()
			if err != nil || tok.Kind() != '"' {
				return nil, errInvalid
			}
			out = append(out, tok.String())
		}
		_, err := dec.ReadToken()
		return out, err
	default:
		return nil, errInvalid
	}
}

func readStringOrSlice(dec *jsontext.Decoder) ([]string, error) {
	switch dec.PeekKind() {
	case 'n':
		_, err := dec.ReadToken()
		return nil, err
	case '"':
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		return []string{tok.String()}, nil
	case '[':
		return readOptStringSlice(dec)
	default:
		return nil, errInvalid
	}
}

func readOrgClaim(dec *jsontext.Decoder) ([]string, error) {
	switch dec.PeekKind() {
	case 'n':
		_, err := dec.ReadToken()
		return nil, err
	case '"':
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		if s := tok.String(); s != "" {
			return []string{s}, nil
		}
		return nil, nil
	case '[':
		return readOptStringSlice(dec)
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var names []string
		for dec.PeekKind() != '}' {
			kTok, err := dec.ReadToken()
			if err != nil || kTok.Kind() != '"' {
				return nil, errInvalid
			}
			names = append(names, kTok.String())
			if err := dec.SkipValue(); err != nil {
				return nil, errInvalid
			}
		}
		_, err := dec.ReadToken()
		return names, err
	default:
		return nil, errInvalid
	}
}

func readRoleObject(dec *jsontext.Decoder) ([]string, error) {
	switch dec.PeekKind() {
	case 'n':
		_, err := dec.ReadToken()
		return nil, err
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var roles []string
		for dec.PeekKind() != '}' {
			kTok, err := dec.ReadToken()
			if err != nil || kTok.Kind() != '"' {
				return nil, errInvalid
			}
			if kTok.String() == "roles" {
				r, err := readOptStringSlice(dec)
				if err != nil {
					return nil, err
				}
				roles = r
			} else if err := dec.SkipValue(); err != nil {
				return nil, err
			}
		}
		_, err := dec.ReadToken()
		return roles, err
	default:
		return nil, errInvalid
	}
}

func readResourceAccess(dec *jsontext.Decoder, clientID string) ([]string, error) {
	if clientID == "" {
		return nil, dec.SkipValue()
	}
	switch dec.PeekKind() {
	case 'n':
		_, err := dec.ReadToken()
		return nil, err
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var roles []string
		for dec.PeekKind() != '}' {
			kTok, err := dec.ReadToken()
			if err != nil || kTok.Kind() != '"' {
				return nil, errInvalid
			}
			if kTok.String() == clientID {
				r, err := readRoleObject(dec)
				if err != nil {
					return nil, err
				}
				roles = r
			} else if err := dec.SkipValue(); err != nil {
				return nil, err
			}
		}
		_, err := dec.ReadToken()
		return roles, err
	default:
		return nil, errInvalid
	}
}

func readCustomClaimValue(dec *jsontext.Decoder) (string, bool) {
	switch dec.PeekKind() {
	case '"':
		tok, err := dec.ReadToken()
		if err != nil {
			return "", false
		}
		return tok.String(), true
	case 't', 'f':
		tok, err := dec.ReadToken()
		if err != nil {
			return "", false
		}
		return strconv.FormatBool(tok.Bool()), true
	case '0':
		tok, err := dec.ReadToken()
		if err != nil {
			return "", false
		}
		f, err := tok.Float()
		if err != nil {
			return "", false
		}
		return strconv.FormatFloat(f, 'f', -1, 64), true
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return "", false
		}
		var parts []string
		for dec.PeekKind() != ']' {
			tok, err := dec.ReadToken()
			if err != nil || tok.Kind() != '"' {
				return "", false
			}
			s := tok.String()
			if s == "" || strings.Contains(s, ",") || !safeHeaderValue(s) {
				return "", false
			}
			parts = append(parts, s)
		}
		if _, err := dec.ReadToken(); err != nil {
			return "", false
		}
		return strings.Join(parts, ","), true
	default:
		return "", false
	}
}
