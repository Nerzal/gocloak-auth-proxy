# gocloak-auth-proxy

A security-first, high-performance Go authentication proxy built specifically for **Keycloak** using `github.com/Nerzal/gocloak/v15` and the Go standard library — with **minimal third-party dependencies** (enforced via `depguard`).

It supports **Forward-Auth** (Traefik / Nginx `auth_request`), **Reverse-Proxy**, and **Browser SSO (OIDC Authorization Code + PKCE)** out of the box.

## Features

- **Zero-Network, Lock-Free JWT Hot Path:** Local signature verification against an immutable `atomic.Pointer` JWKS snapshot with coalesced, rate-limited on-demand rotation and bounded exponential backoff.
- **Full Asymmetric JWS Support:** `RS256/384/512`, `PS256/384/512`, `ES256/384/512`, and `EdDSA` (`OKP/Ed25519`). Strictly rejects `none` and `HS*` algorithms as well as `crit`/`b64`/`jku`/`x5u`/`jwk` header extensions.
- **Keycloak-Native Authorization:**
  - Realm & client roles (`all` or `any` match mode)
  - Groups (`all` or `any`), OAuth `scope`, `acr` (MFA level), `email_verified`, `azp`, and Keycloak 26+ `organization`
  - Optional online **Token Introspection** (`RetrospectToken`) with a bounded, SHA-256-keyed TTL cache & singleflight coalescing
  - Optional **Keycloak UMA 2.0** resource authorization (`GetRequestingPartyPermissions`, including `#method:<HTTP_METHOD>` scopes)
  - Path/method **ACLs** (`PUBLIC_PATHS`, `OPTIONAL_AUTH_PATHS`, `ALLOW_CORS_PREFLIGHT`, `ROUTE_RULES`) with path-traversal and delimiter-injection protection
- **Browser SSO (OIDC):** Authorization Code Flow with PKCE (`S256`), `nonce`/`iss`/`aud`/`exp` validation, AES-256-GCM encrypted chunked session cookies (handles >4 KB Keycloak tokens), coalesced refresh-token rotation, CSRF-protected `/oauth2/logout`, and automatic proxy-cookie stripping before upstream forwarding.
- **Hardened & Observable:** Header spoofing prevention (including `_`/`-` WSGI/CGI alias normalization and `X-Real-IP`), TLS 1.2+ with custom CA bundles, HSTS on TLS listeners, redacted JSON logging (`log/slog`), zero-dependency Prometheus `/metrics`, `/healthz`, `/readyz`, and nonroot `distroless` container packaging.

---

## Installation

### Container Image (GHCR — Recommended)

Multi-arch (`linux/amd64`, `linux/arm64`), nonroot `distroless` images are published to GitHub Container Registry on every release:

```sh
docker pull ghcr.io/nerzal/gocloak-auth-proxy:latest
# or pin to a specific release tag:
docker pull ghcr.io/nerzal/gocloak-auth-proxy:v0.1.0
```

### Prebuilt Static Binaries (GitHub Releases)

Static (`CGO_ENABLED=0`) binaries for Linux and macOS (`amd64` / `arm64`) are published on the [GitHub Releases](https://github.com/Nerzal/gocloak-auth-proxy/releases) page alongside `checksums.txt` and GitHub build provenance attestations:

```sh
VERSION=0.1.0
OS=linux   # linux or darwin
ARCH=amd64 # amd64 or arm64

curl -fsSLO "https://github.com/Nerzal/gocloak-auth-proxy/releases/download/v${VERSION}/gocloak-auth-proxy_${VERSION}_${OS}_${ARCH}.tar.gz"
curl -fsSLO "https://github.com/Nerzal/gocloak-auth-proxy/releases/download/v${VERSION}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt
tar -xzf "gocloak-auth-proxy_${VERSION}_${OS}_${ARCH}.tar.gz" gocloak-auth-proxy
./gocloak-auth-proxy --version
```

Optionally verify build provenance with the GitHub CLI:

```sh
gh attestation verify "gocloak-auth-proxy_${VERSION}_${OS}_${ARCH}.tar.gz" -R Nerzal/gocloak-auth-proxy
gh attestation verify oci://ghcr.io/nerzal/gocloak-auth-proxy:v${VERSION} -R Nerzal/gocloak-auth-proxy
```

### Go Install

Requires Go 1.27 or newer:

```sh
go install github.com/Nerzal/gocloak-auth-proxy/cmd/gocloak-auth-proxy@latest
```

---

## Quick Start

### 1. Container (Forward-Auth Mode)

```sh
docker run --rm -p 8080:8080 \
  -e ISSUER=https://keycloak.example.com/realms/myrealm \
  -e AUDIENCE=my-api \
  ghcr.io/nerzal/gocloak-auth-proxy:latest
```

### 2. Forward-Auth Mode (Binary / Source)

```sh
export ISSUER=https://keycloak.example.com/realms/myrealm
export AUDIENCE=my-api
gocloak-auth-proxy
```

### 3. Reverse-Proxy Mode (with RBAC & Custom Claims)

```sh
export ISSUER=https://keycloak.example.com/realms/myrealm
export AUDIENCE=my-api
export UPSTREAM_URL=http://127.0.0.1:3000
export REQUIRED_REALM_ROLES=reader
export CUSTOM_CLAIM_HEADERS="X-Tenant-ID=tenant_id"
gocloak-auth-proxy
```

### 4. Browser SSO Mode (OIDC + PKCE + Encrypted Cookies)

```sh
export ISSUER=https://keycloak.example.com/realms/myrealm
export AUDIENCE=my-web-app
export CLIENT_ID=my-web-app
export CLIENT_SECRET=your-client-secret
export UPSTREAM_URL=http://127.0.0.1:3000
export OIDC_ENABLED=true
export OIDC_REDIRECT_URL=https://app.example.com/oauth2/callback
export OIDC_COOKIE_SECRET="$(openssl rand -base64 32)"
gocloak-auth-proxy
```

---

## Endpoints

| Path | Auth | Description |
| --- | --- | --- |
| `/healthz` | Public | Liveness probe (`200 OK`) |
| `/readyz` | Public | Readiness probe (`200 OK` when a valid, unexpired JWKS snapshot is loaded; otherwise `503`) |
| `/auth` | Protected | Forward-Auth endpoint (active when `UPSTREAM_URL` is omitted) |
| `/*` | Protected | Reverse-Proxy target (active when `UPSTREAM_URL` is set) |
| `/oauth2/start`, `/oauth2/callback`, `/oauth2/logout` | OIDC Flow | Browser SSO endpoints (active when `OIDC_ENABLED=true`) |
| `/metrics` | Dedicated Port | Prometheus / OpenMetrics exposition (served on `METRICS_ADDR` when configured) |

---

## Ingress Integration

### Nginx (`auth_request`)

```nginx
location = /_auth {
    internal;
    proxy_pass http://auth_proxy/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Authorization $http_authorization;
}

location / {
    auth_request /_auth;
    auth_request_set $auth_user $upstream_http_x_auth_request_user;
    auth_request_set $auth_email $upstream_http_x_auth_request_email;
    auth_request_set $auth_groups $upstream_http_x_auth_request_groups;
    auth_request_set $auth_roles $upstream_http_x_auth_request_roles;

    # Do not forward arbitrary client headers, including spoofed identity headers.
    proxy_pass_request_headers off;
    proxy_set_header Content-Type $http_content_type;
    proxy_set_header Accept $http_accept;
    proxy_set_header X-Auth-Request-User $auth_user;
    proxy_set_header X-Auth-Request-Email $auth_email;
    proxy_set_header X-Auth-Request-Groups $auth_groups;
    proxy_set_header X-Auth-Request-Roles $auth_roles;
    proxy_set_header Authorization "";
    proxy_pass http://application;
}
```

### Traefik (`forwardAuth`)

```yaml
http:
  middlewares:
    keycloak-auth:
      forwardAuth:
        address: "http://auth-proxy:8080/auth"
        trustForwardHeader: false
        authResponseHeaders:
          - "X-Auth-Request-User"
          - "X-Auth-Request-Email"
          - "X-Auth-Request-Groups"
          - "X-Auth-Request-Roles"
```

---

## Configuration Reference

### Core

| Variable | Default | Description |
| --- | --- | --- |
| `CONFIG_FILE` | `""` | Optional path to a strict JSON configuration file (unknown fields rejected; environment variables override file values). |
| `ISSUER` | *(required)* | Exact Keycloak realm issuer URL, e.g. `https://keycloak.example.com/realms/myrealm`. HTTPS required except for localhost/loopback. |
| `AUDIENCE` | *(required)* | Expected `aud` claim. Configure an Audience protocol mapper in Keycloak if your tokens only emit `aud: "account"`. |
| `UPSTREAM_URL` | `""` | Fixed reverse-proxy upstream URL. When omitted, runs in forward-auth mode on `/auth`. |
| `LISTEN_ADDR` | `:8080` | Proxy listen address (`host:port`). |
| `CLIENT_ID` | `""` | Keycloak client ID; required for client roles, introspection, or OIDC SSO. |
| `CLIENT_SECRET` | `""` | Keycloak client secret; required for `INTROSPECTION_ENABLED` and confidential OIDC clients. |
| `ALLOWED_ALGORITHMS` | `RS256,ES256` | Comma-separated allowed JWS algorithms (`RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `EdDSA`). |
| `JWKS_REFRESH_INTERVAL` | `5m` | Periodic JWKS refresh interval (`1s`–`12h`). |
| `CLOCK_SKEW` | `30s` | Token validation leeway (`0s`–`30s`). |

### Authorization & Claims

| Variable | Default | Description |
| --- | --- | --- |
| `REQUIRED_REALM_ROLES` | `""` | Comma-separated required Keycloak realm roles. |
| `REQUIRED_CLIENT_ROLES` | `""` | Comma-separated required roles for `CLIENT_ID`. |
| `ROLE_MATCH_MODE` | `all` | Role matching logic: `all` (AND) or `any` (OR). |
| `REQUIRED_GROUPS` | `""` | Comma-separated required groups. |
| `GROUP_MATCH_MODE` | `all` | Group matching logic: `all` (AND) or `any` (OR). |
| `REQUIRED_SCOPES` | `""` | Comma-separated required OAuth scopes (from `scope` claim). |
| `REQUIRED_ACR` | `""` | Comma-separated accepted `acr` (MFA / LoA) values. |
| `REQUIRED_AMR` | `""` | Comma-separated required `amr` (Authentication Methods References, e.g. `mfa,hwk`) values. |
| `REQUIRE_EMAIL_VERIFIED` | `false` | Require `email_verified: true`. |
| `REQUIRED_AZP` | `""` | Require exact `azp` (authorized party) match. |
| `REQUIRED_ORGANIZATION` | `""` | Require Keycloak 26+ `organization` claim membership. |

### Identity Headers & Token Forwarding

| Variable | Default | Description |
| --- | --- | --- |
| `HEADER_USER` | `X-Auth-Request-User` | Header name for verified `preferred_username` (fallback `sub`). |
| `HEADER_EMAIL` | `X-Auth-Request-Email` | Header name for verified `email`. |
| `HEADER_GROUPS` | `X-Auth-Request-Groups` | Header name for verified comma-separated `groups`. |
| `HEADER_ROLES` | `X-Auth-Request-Roles` | Header name for verified comma-separated realm + client `roles`. |
| `CUSTOM_CLAIM_HEADERS` | `""` | Comma-separated `Header-Name=claim_name` mappings forwarded from verified JWT claims. |
| `PASS_ACCESS_TOKEN` | `false` | Forward verified access token (`Authorization` in reverse-proxy, `X-Auth-Request-Access-Token` in forward-auth). |

### Keycloak Online Authorization & Path ACLs

| Variable | Default | Description |
| --- | --- | --- |
| `INTROSPECTION_ENABLED` | `false` | Enable online Keycloak `RetrospectToken` check after local RBAC validation. |
| `INTROSPECTION_CACHE_TTL` | `15s` | Bounded SHA-256-keyed introspection cache TTL (`0s`–`5m`). |
| `UMA_ENABLED` | `false` | Enable Keycloak UMA 2.0 resource authorization (requires `UPSTREAM_URL`). |
| `UMA_METHOD_SCOPE` | `false` | Append `#method:<HTTP_METHOD>` scope to UMA URI permission checks. |
| `PUBLIC_PATHS` | `""` | Comma-separated path patterns (`/public/*`, `/status`) bypassing authentication. |
| `OPTIONAL_AUTH_PATHS` | `""` | Comma-separated patterns allowing anonymous requests while strictly validating tokens if present. |
| `ALLOW_CORS_PREFLIGHT` | `false` | Allow CORS `OPTIONS` preflight requests without authentication. |
| `ROUTE_RULES` | `""` | Semicolon-separated route ACLs supporting `realm:`, `client:`, `acr:`, and `amr:`, e.g. `POST:/admin/*=realm:admin,acr:aal2,amr:mfa` (requires `UPSTREAM_URL`). |

### Browser SSO (OIDC)

| Variable | Default | Description |
| --- | --- | --- |
| `OIDC_ENABLED` | `false` | Enable Authorization Code + PKCE browser SSO (`/oauth2/start`, `/oauth2/callback`, `/oauth2/logout`, `/oauth2/backchannel-logout`). |
| `OIDC_REDIRECT_URL` | `""` | Required when `OIDC_ENABLED=true`. Absolute callback URL (e.g. `https://app.example.com/oauth2/callback`). |
| `OIDC_COOKIE_SECRET` | `""` | Required when `OIDC_ENABLED=true`. Secret for AES-256-GCM cookie encryption (min 32 characters). |
| `OIDC_POST_LOGOUT_URL` | `/` | Safe relative path or absolute HTTP(S) URL redirected to after `/oauth2/logout`. |
| `OIDC_COOKIE_NAME` | `__Host-gocloak_session` | Session cookie name (defaults to `gocloak_session` when `OIDC_COOKIE_SECURE=false` or `OIDC_COOKIE_DOMAIN` is set). |
| `OIDC_COOKIE_DOMAIN` | `""` | Optional cookie `Domain` attribute (e.g. `.example.com`) for multi-subdomain SSO (incompatible with `__Host-` prefix). |
| `OIDC_COOKIE_SECURE` | `true` | Set `Secure` attribute on OIDC cookies (`false` for local HTTP development only). |
| `OIDC_COOKIE_SAMESITE` | `lax` | Cookie `SameSite` policy: `lax`, `strict`, or `none` (requires `OIDC_COOKIE_SECURE=true`). |
| `OIDC_SCOPES` | `openid,profile,email` | Comma-separated OIDC scopes requested during login. |
| `OIDC_SESSION_MAX_AGE` | `24h` | Absolute session lifetime enforced both on cookies and inside the encrypted payload. |
| `OIDC_REDIRECT` | `true` | Redirect unauthenticated HTML `GET` requests (`302`) to `/oauth2/start` instead of returning `401`. |
| `OIDC_ALLOWED_REDIRECT_DOMAINS` | `""` | Comma-separated allowlist of redirect hosts or `.suffix` domains (e.g. `app1.example.com,.example.com`) for multi-domain SSO. |

### TLS, Timeouts & Observability

| Variable | Default | Description |
| --- | --- | --- |
| `KEYCLOAK_CA_FILE` | `""` | Optional PEM CA bundle for TLS connections to Keycloak. |
| `KEYCLOAK_CLIENT_CERT_FILE` / `KEYCLOAK_CLIENT_KEY_FILE` | `""` | Optional mTLS client certificate and private key for connections to Keycloak. |
| `UPSTREAM_CA_FILE` | `""` | Optional PEM CA bundle for TLS connections to the reverse-proxy upstream. |
| `UPSTREAM_CLIENT_CERT_FILE` / `UPSTREAM_CLIENT_KEY_FILE` | `""` | Optional mTLS client certificate and private key for connections to the upstream. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | `""` | Optional TLS 1.2+ certificate and key for the proxy listener (enables HSTS automatically). |
| `METRICS_ADDR` | `""` | Optional dedicated listen address for Prometheus `/metrics` (e.g. `:9090`); keep internal, never expose publicly. |
| `LOG_LEVEL` | `info` | Structured JSON log level: `debug`, `info`, `warn`, `error` (correlates W3C `traceparent` as `trace_id`). |
| `SERVER_READ_HEADER_TIMEOUT` / `SERVER_READ_TIMEOUT` | `5s` / `15s` | Inbound HTTP server header and body read timeouts. |
| `SERVER_WRITE_TIMEOUT` / `SERVER_IDLE_TIMEOUT` | `30s` / `60s` | Inbound HTTP write/idle timeouts (set `SERVER_WRITE_TIMEOUT=0s` for WebSockets/SSE). |
| `UPSTREAM_HEADER_TIMEOUT` / `UPSTREAM_REQUEST_TIMEOUT` | `15s` / `25s` | Outbound reverse-proxy timeouts (set `UPSTREAM_REQUEST_TIMEOUT=0s` for WebSockets/SSE). |

---

## Benchmarks

### Go Microbenchmarks

Measured with `make bench` (`go test -run '^$' -bench . -benchmem ./...`) on Go 1.27 (`linux/amd64`, Intel Xeon 6985P-C):

| Benchmark | Time / Op | Bytes / Op | Allocs / Op | Scope |
| --- | ---: | ---: | ---: | --- |
| `BenchmarkPolicy` | `125.6 ns` | `0 B` | `0` | Path normalization + ACL mode + route role check |
| `BenchmarkIntrospectorCacheHit` | `226.7 ns` | `0 B` | `0` | Parallel `RLock` introspection cache hit (SHA-256 token lookup) |
| `BenchmarkVerifyCached` | `463.1 ns` | `0 B` | `0` | Parallel verified-token cache hit (SHA-256 + `exp`/`nbf` + JWKS key-identity check) |
| `BenchmarkForwardAuth` | `1.62 µs` | `2336 B` | `17` | Header scrubbing + pre-canonicalized identity injection (`httptest.ResponseRecorder`) |
| `BenchmarkReadSession` | `2.76 µs` | `1328 B` | `3` | OIDC pooled base64 + in-place AES-256-GCM decrypt + `encoding/json/v2` decode |
| `BenchmarkVerify/RS256` | `30.0 µs` | `1728 B` | `33` | Cold RS256 (2048-bit) JWS signature + streaming `jsontext` claims + RBAC |
| `BenchmarkVerifyEdDSA` | `45.5 µs` | `624 B` | `24` | Cold Ed25519 (`EdDSA`) JWS verify + single-pass `CUSTOM_CLAIM_HEADERS` |
| `BenchmarkVerify/ES256` | `67.7 µs` | `1536 B` | `44` | Cold ES256 (P-256) JWS signature + streaming `jsontext` claims + RBAC |

### Live Head-to-Head Cross-Language Comparison

Measured with `make bench-compare` on the same machine (`linux/amd64`, Intel Xeon 6985P-C, `GOMAXPROCS=2`, `C=32`, `D=5s`, 2048-bit RS256 Bearer JWT, local mock Keycloak JWKS & upstream, 0 errors across all runs):

| Proxy | Runtime | Mode | Token Mode | RPS | p50 | p95 | p99 | Idle / Load RSS |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| **`gocloak-auth-proxy` (Warm)** | **Go 1.27** | Forward-Auth | Warm | **30,797** | **0.82 ms** | **2.79 ms** | **4.18 ms** | **9.1 / 15.4 MB** |
| **`gocloak-auth-proxy` (Cold)** | **Go 1.27** | Forward-Auth | Cold (2000) | **18,616** | **1.53 ms** | **4.08 ms** | **5.77 ms** | **9.0 / 15.9 MB** |
| `rust-auth-proxy` (Axum + `jsonwebtoken`) | Rust 1.100 | Forward-Auth | Cold (2000) | 26,232 | 1.14 ms | 2.28 ms | 3.25 ms | 2.5 / 3.7 MB |
| `java-auth-proxy` (`HttpServer`) | Java 17 | Forward-Auth | Cold (2000) | 8,876 | 3.16 ms | 7.59 ms | 12.51 ms | 38.2 / 104.4 MB |
| `oauth2-proxy v7.15.6` | Go | Forward-Auth | Warm | 7,541 | 3.61 ms | 9.88 ms | 14.92 ms | 19.8 / 27.3 MB |
| `python-auth-proxy` (Uvicorn + PyJWT) | Python 3.11 | Forward-Auth | Cold (2000) | 5,567 | 5.34 ms | 10.21 ms | 12.23 ms | 14.7 MB (master) |
| **`gocloak-auth-proxy` (Warm)** | **Go 1.27** | Reverse-Proxy | Warm | **13,288** | **2.11 ms** | **5.02 ms** | **6.80 ms** | **9.1 / 16.3 MB** |
| **`gocloak-auth-proxy` (Cold)** | **Go 1.27** | Reverse-Proxy | Cold (2000) | **9,922** | **2.91 ms** | **6.32 ms** | **8.44 ms** | **9.0 / 16.2 MB** |
| `rust-auth-proxy` (Axum + `reqwest`) | Rust 1.100 | Reverse-Proxy | Cold (2000) | 12,385 | 2.42 ms | 4.41 ms | 5.55 ms | 2.4 / 6.1 MB |
| `oauth2-proxy v7.15.6` | Go | Reverse-Proxy | Warm | 2,713 | 11.05 ms | 22.66 ms | 28.75 ms | 19.8 / 27.8 MB |
| `java-auth-proxy` (`HttpClient`) | Java 17 | Reverse-Proxy | Cold (2000) | 1,421 | 20.01 ms | 41.15 ms | 50.29 ms | 37.8 / 112.2 MB |
| `python-auth-proxy` (Uvicorn + `httpx`) | Python 3.11 | Reverse-Proxy | Cold (2000) | 837 | 17.18 ms | 129.99 ms | 210.00 ms | 14.7 MB (master) |

### Running Benchmarks & Profiles Locally

```sh
make bench            # Go microbenchmarks with allocation stats
make bench-profile    # Capture CPU & memory pprof profiles + top summaries
make bench-isolated   # Isolated live HTTP benchmark (gocloak-auth-proxy Warm & Cold)
make bench-compare    # Cross-language benchmark (Go, Rust, Java, Python)

# Non-isolated benchmark against a real Keycloak 26 instance:
docker compose -f bench/docker-compose.keycloak.yml up -d
make bench-keycloak
```

---

## Security Model

- **Fail-Closed by Default:** Missing/malformed tokens, wrong `typ` (only `"Bearer"` is accepted), expired claims, unknown `kid`, JWKS/introspection/UMA errors, or path-traversal attempts (`..`, `%2f`, `%2e`, `%5c`, `%23`, `#`, `%00`) are rejected with `401`/`403`.
- **Anti-Spoofing:** All inbound `X-Auth-Request-*`, `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, `Authorization`, and configured custom identity headers (including `_`/`-` aliases) are stripped before verification and before upstream forwarding. In OIDC mode, proxy session/state cookies are stripped from outbound upstream requests.
- **Zero Secret Leakage:** Structured JSON logs redact sensitive keys (`token`, `authorization`, `cookie`, `secret`, `password`, `email`, `bearer`, `jwt`, `credential`, `session`) and string values containing `Bearer ` tokens. Client error responses never expose internal or upstream details.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

---

## Development

```sh
make test        # Unit tests
make test-race   # Race detector + coverage
make bench       # Benchmarks with memory allocation stats
make lint        # golangci-lint (includes depguard allowlist & staticcheck)
make security    # govulncheck + gosec
make check       # Full local quality gate (lint, security, test-race, bench, build)
```

CI runs `test` (`-race`), `lint`, `security` (`govulncheck` + `gosec`), and `CodeQL` on every push and pull request.
