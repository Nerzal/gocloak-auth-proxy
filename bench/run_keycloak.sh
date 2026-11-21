#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${ROOT_DIR}/bench"
BIN_CACHE="${BENCH_BIN_CACHE:-/tmp/gocloak-bench-bins}"
WORK_DIR="${BENCH_WORK_DIR:-/tmp/gocloak-bench-work}"

KEYCLOAK_URL="${KEYCLOAK_URL:-http://127.0.0.1:18080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-bench}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID:-bench-api}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-bench-secret}"
KEYCLOAK_USERNAME="${KEYCLOAK_USERNAME:-benchuser}"
KEYCLOAK_PASSWORD="${KEYCLOAK_PASSWORD:-benchpass}"
CONCURRENCY="${CONCURRENCY:-32}"
DURATION="${DURATION:-5s}"
WARMUP="${WARMUP:-1s}"

mkdir -p "$WORK_DIR" "$BIN_CACHE"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

wait_ready() {
  local url="$1"
  for _ in $(seq 1 80); do
    if curl -fsS --max-time 1 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "ERROR: timed out waiting for $url" >&2
  return 1
}

echo "==> Checking live Keycloak at ${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}..."
if ! curl -fsS --max-time 3 "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration" >/dev/null 2>&1; then
  echo "ERROR: Keycloak is not reachable at ${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}" >&2
  echo "Start it with: docker compose -f bench/docker-compose.keycloak.yml up -d" >&2
  exit 1
fi

(cd "$ROOT_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BIN_CACHE}/gocloak-auth-proxy" ./cmd/gocloak-auth-proxy)
(cd "$BENCH_DIR" && go build -o "${BIN_CACHE}/benchrun" ./cmd/benchrun)

# Start local upstream only (Keycloak is live!)
INFO_FILE="${WORK_DIR}/kc_upstream_info.json"
"${BIN_CACHE}/benchrun" -mode=mocks -kc-addr=127.0.0.1:18281 -up-addr=127.0.0.1:18282 -cold-tokens=0 -info-file="$INFO_FILE" &
PIDS+=($!)
for _ in $(seq 1 30); do [[ -s "$INFO_FILE" ]] && break; sleep 0.1; done
UPSTREAM_URL="$(python3 -c "import json; print(json.load(open('$INFO_FILE'))['upstream_url'])")"

TOKEN="$("${BIN_CACHE}/benchrun" -mode=keycloak-token \
  -keycloak-url="$KEYCLOAK_URL" \
  -realm="$KEYCLOAK_REALM" \
  -client-id="$KEYCLOAK_CLIENT_ID" \
  -client-secret="$KEYCLOAK_CLIENT_SECRET" \
  -username="$KEYCLOAK_USERNAME" \
  -password="$KEYCLOAK_PASSWORD")"

ISSUER="${KEYCLOAK_URL%/}/realms/${KEYCLOAK_REALM}"

run_kc_case() {
  local label="$1"
  local mode="$2"
  local port="$3"
  local path="$4"
  shift 4

  "$@" >"${WORK_DIR}/kc_${port}.log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  wait_ready "http://127.0.0.1:${port}/readyz"

  "${BIN_CACHE}/benchrun" -mode=load -name="$label" -bench-mode="$mode" \
    -target-url="http://127.0.0.1:${port}${path}" \
    -target-pid="$pid" -token="$TOKEN" \
    -c="$CONCURRENCY" -w="$WARMUP" -d="$DURATION"

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

echo ""
echo "### Live Keycloak Benchmark (${ISSUER}, C=${CONCURRENCY}, D=${DURATION})"
echo ""
echo "| Scenario | Mode | Token | RPS | p50 | p95 | p99 | Idle RSS | Load RSS | Errors |"
echo "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"

run_kc_case "gocloak-auth-proxy (Warm JWKS)" "forward_auth" 18201 "/auth" \
  env ISSUER="$ISSUER" AUDIENCE="$KEYCLOAK_CLIENT_ID" LISTEN_ADDR="127.0.0.1:18201" TOKEN_CACHE_SIZE=4096 LOG_LEVEL=error \
  "${BIN_CACHE}/gocloak-auth-proxy"

run_kc_case "gocloak-auth-proxy (Cold JWKS)" "forward_auth" 18202 "/auth" \
  env ISSUER="$ISSUER" AUDIENCE="$KEYCLOAK_CLIENT_ID" LISTEN_ADDR="127.0.0.1:18202" TOKEN_CACHE_SIZE=0 LOG_LEVEL=error \
  "${BIN_CACHE}/gocloak-auth-proxy"

run_kc_case "gocloak-auth-proxy (Warm JWKS)" "reverse_proxy" 18203 "/api/items" \
  env ISSUER="$ISSUER" AUDIENCE="$KEYCLOAK_CLIENT_ID" UPSTREAM_URL="$UPSTREAM_URL" LISTEN_ADDR="127.0.0.1:18203" TOKEN_CACHE_SIZE=4096 LOG_LEVEL=error \
  "${BIN_CACHE}/gocloak-auth-proxy"

run_kc_case "gocloak-auth-proxy (Online Introspection, 0s TTL)" "introspection" 18204 "/auth" \
  env ISSUER="$ISSUER" AUDIENCE="$KEYCLOAK_CLIENT_ID" CLIENT_ID="$KEYCLOAK_CLIENT_ID" CLIENT_SECRET="$KEYCLOAK_CLIENT_SECRET" \
      INTROSPECTION_ENABLED=true INTROSPECTION_CACHE_TTL=0s TOKEN_CACHE_SIZE=4096 \
      LISTEN_ADDR="127.0.0.1:18204" LOG_LEVEL=error \
  "${BIN_CACHE}/gocloak-auth-proxy"
