# gocloak-auth-proxy

A Go authentication proxy for Keycloak-issued bearer tokens. It supports
forward-auth integration or proxying requests to an upstream service.

## Configuration

Configure the process with environment variables:

| Variable | Description |
| --- | --- |
| `ISSUER` | Required. Exact Keycloak realm issuer URL, e.g. `https://keycloak.example.com/realms/myrealm`. HTTPS is required except for HTTP on localhost or loopback. |
| `AUDIENCE` | Required. Expected token audience. |
| `UPSTREAM_URL` | Optional. Upstream URL; when omitted, run in forward-auth mode. |
| `LISTEN_ADDR` | Listen address; default `:8080`. |
| `CLIENT_ID` | Keycloak client ID; required when `REQUIRED_CLIENT_ROLES` is set. |
| `REQUIRED_REALM_ROLES` | Comma-separated required realm roles. |
| `REQUIRED_CLIENT_ROLES` | Comma-separated required roles for `CLIENT_ID`. |
| `HEADER_USER` | Optional. Identity header name for the verified username/subject; default `X-Auth-Request-User`. |
| `HEADER_EMAIL` | Optional. Identity header name for the verified email; default `X-Auth-Request-Email`. |
| `HEADER_GROUPS` | Optional. Identity header name for verified groups; default `X-Auth-Request-Groups`. |
| `HEADER_ROLES` | Optional. Identity header name for verified roles; default `X-Auth-Request-Roles`. |
| `JWKS_REFRESH_INTERVAL` | JWKS refresh interval as a Go duration; default `5m`, allowed `1s`–`12h`. |
| `CLOCK_SKEW` | Token validation clock tolerance as a Go duration; default `30s`, allowed `0s`–`30s`. |

All configured roles are required. Tokens must be access tokens (`typ: "Bearer"`)
with valid `iss`, `aud`, `exp`, and `iat` claims (`nbf` is validated when
present; configure an Audience protocol mapper in Keycloak if your realm tokens
do not include the target `AUDIENCE`). Do not send access tokens to untrusted
services. Use HTTPS for the issuer in production, and terminate TLS at a trusted
ingress. Restrict access to the proxy and upstream to trusted networks; do not
allow clients to bypass the proxy. The service itself listens over HTTP.

`/healthz` and `/readyz` are unauthenticated health endpoints. Without an
upstream, use `/auth` as the forward-auth endpoint. With `UPSTREAM_URL` set,
other requests are reverse-proxied to that upstream (note that `/healthz` and
`/readyz` are reserved by the proxy).

## Architecture and integration

The proxy retrieves Keycloak realm signing keys and validates bearer tokens
locally. Successful authentication exposes the verified user, email, groups and
roles as `X-Auth-Request-User`, `X-Auth-Request-Email`,
`X-Auth-Request-Groups`, and `X-Auth-Request-Roles` (or the configured
`HEADER_*` names). In reverse-proxy mode, client-supplied identity, forwarding
(`Forwarded`, `X-Forwarded-*`, `X-Real-IP`, including underscore aliases), and
bearer headers are removed before forwarding; verified identity headers are then
added.

For forward-auth, the ingress must pass the bearer `Authorization` header to
`/auth`, deny access when it fails, and overwrite any client-supplied identity
headers with the response values. For example, with nginx's `auth_request`
module, replace the upstream names below with your trusted services:

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

This example intentionally forwards only the listed request headers. Add other
headers only after reviewing whether clients may safely control them.

With Traefik's `forwardAuth` middleware:

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

In reverse-proxy mode instead, set `UPSTREAM_URL` to the application URL and
route traffic to the proxy; no ingress auth subrequest is needed.

## Run

Go 1.26 or newer is required.

```sh
export ISSUER=https://keycloak.example.com/realms/myrealm
export AUDIENCE=my-api
go run ./cmd/gocloak-auth-proxy
```

For a container:

```sh
docker build -t gocloak-auth-proxy .
docker run --rm -p 8080:8080 \
  -e ISSUER=https://keycloak.example.com/realms/myrealm \
  -e AUDIENCE=my-api \
  gocloak-auth-proxy
```

## Development

Run `make test`, `make test-race`, `make bench`, or `make build`. `make check`
combines lint, security checks, race-enabled tests, benchmarks, and build. `make lint`
requires golangci-lint v2.15.0; `make vuln` requires govulncheck v1.7.0; and
`make security` also requires gosec v2.29.0. CI runs these checks and CodeQL.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.
