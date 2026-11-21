#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${ROOT_DIR}/bench"
WORK_DIR="${BENCH_WORK_DIR:-/tmp/gocloak-bench-work}"
BIN_CACHE="${BENCH_BIN_CACHE:-/tmp/gocloak-bench-bins}"

CONCURRENCY="${CONCURRENCY:-32}"
DURATION="${DURATION:-5s}"
WARMUP="${WARMUP:-1s}"
ONLY_GOCLOAK="${ONLY_GOCLOAK:-0}"
export GOMAXPROCS="${GOMAXPROCS:-2}"

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

echo "==> Building gocloak-auth-proxy and benchrun..."
(cd "$ROOT_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BIN_CACHE}/gocloak-auth-proxy" ./cmd/gocloak-auth-proxy)
(cd "$BENCH_DIR" && go build -o "${BIN_CACHE}/benchrun" ./cmd/benchrun)

# Start mock Keycloak + mock upstream
INFO_FILE="${WORK_DIR}/mock_info.json"
TOKENS_FILE="${WORK_DIR}/cold_tokens.txt"
rm -f "$INFO_FILE" "$TOKENS_FILE"

"${BIN_CACHE}/benchrun" \
  -mode=mocks \
  -kc-addr=127.0.0.1:18081 \
  -up-addr=127.0.0.1:18082 \
  -cold-tokens=2000 \
  -info-file="$INFO_FILE" \
  -out-tokens-file="$TOKENS_FILE" &
MOCK_PID=$!
PIDS+=("$MOCK_PID")

for _ in $(seq 1 50); do
  [[ -s "$INFO_FILE" ]] && break
  sleep 0.1
done

ISSUER="$(python3 -c "import json; print(json.load(open('$INFO_FILE'))['issuer'])")"
JWKS_URL="$(python3 -c "import json; print(json.load(open('$INFO_FILE'))['jwks_url'])")"
UPSTREAM_URL="$(python3 -c "import json; print(json.load(open('$INFO_FILE'))['upstream_url'])")"
AUDIENCE="$(python3 -c "import json; print(json.load(open('$INFO_FILE'))['audience'])")"
WARM_TOKEN="$(python3 -c "import json; print(json.load(open('$INFO_FILE'))['token'])")"

run_target() {
  local label="$1"
  local mode="$2"
  local token_flag="$3"
  local port="$4"
  local ready_path="$5"
  local target_path="$6"
  shift 6

  local log_slug
  log_slug="$(printf '%s' "$label" | tr -cs 'A-Za-z0-9._-' '_')"
  "$@" >"${WORK_DIR}/${log_slug}.log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  wait_ready "http://127.0.0.1:${port}${ready_path}"

  if [[ "$token_flag" == "warm" ]]; then
    "${BIN_CACHE}/benchrun" -mode=load -name="$label" -bench-mode="$mode" \
      -target-url="http://127.0.0.1:${port}${target_path}" \
      -target-pid="$pid" -token="$WARM_TOKEN" \
      -c="$CONCURRENCY" -w="$WARMUP" -d="$DURATION"
  else
    "${BIN_CACHE}/benchrun" -mode=load -name="$label" -bench-mode="$mode" \
      -target-url="http://127.0.0.1:${port}${target_path}" \
      -target-pid="$pid" -tokens-file="$TOKENS_FILE" \
      -c="$CONCURRENCY" -w="$WARMUP" -d="$DURATION"
  fi

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

if [[ "$ONLY_GOCLOAK" != "1" ]]; then
  echo "==> Building competitors (Go / Rust / Java / Python)..."

  # Go: oauth2-proxy (prebuilt release binary for linux/amd64, fallback to go install)
  if [[ ! -x "${BIN_CACHE}/oauth2-proxy" ]]; then
    echo "    Installing oauth2-proxy v7.15.6..."
    if [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]]; then
      curl -fsSL "https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v7.15.6/oauth2-proxy-v7.15.6.linux-amd64.tar.gz" \
        | tar -xz -C "$BIN_CACHE" --strip-components=1 "oauth2-proxy-v7.15.6.linux-amd64/oauth2-proxy" 2>/dev/null \
        || GOBIN="$BIN_CACHE" go install github.com/oauth2-proxy/oauth2-proxy/v7@v7.15.6 || true
    else
      GOBIN="$BIN_CACHE" go install github.com/oauth2-proxy/oauth2-proxy/v7@v7.15.6 || true
    fi
  fi

  # Rust: axum + jsonwebtoken
  if command -v cargo >/dev/null 2>&1 && [[ ! -x "${BIN_CACHE}/rust-auth-proxy" ]]; then
    echo "    Building rust-auth-proxy (--release)..."
    (cd "${BENCH_DIR}/competitors/rust-proxy" && cargo build --release --quiet && cp target/release/rust-auth-proxy "${BIN_CACHE}/rust-auth-proxy") || true
  fi

  # Java 17: OpenJDK HttpServer
  if command -v javac >/dev/null 2>&1; then
    echo "    Compiling java-auth-proxy..."
    mkdir -p "${BIN_CACHE}/java-proxy"
    javac -d "${BIN_CACHE}/java-proxy" "${BENCH_DIR}/competitors/java-proxy/AuthProxy.java" || true
  fi

  # Python: Starlette + Uvicorn + PyJWT
  if command -v uv >/dev/null 2>&1 && [[ ! -x "${BIN_CACHE}/py-venv/bin/uvicorn" ]]; then
    echo "    Setting up Python venv (uvicorn + starlette + httpx + pyjwt[crypto])..."
    uv venv --quiet "${BIN_CACHE}/py-venv" && \
    uv pip install --quiet --python "${BIN_CACHE}/py-venv/bin/python" uvicorn starlette httpx "pyjwt[crypto]" || true
  fi
fi

echo ""
echo "### Isolated Live HTTP Benchmark (GOMAXPROCS=${GOMAXPROCS}, C=${CONCURRENCY}, D=${DURATION}, RS256 2048-bit)"
echo ""
echo "| Proxy | Mode | Token | RPS | p50 | p95 | p99 | Idle RSS | Load RSS | Errors |"
echo "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"

# 1. gocloak-auth-proxy (Warm - default TOKEN_CACHE_SIZE=4096)
run_target "gocloak-auth-proxy (Go, Warm)" "forward_auth" "warm" 18101 "/readyz" "/auth" \
  env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" LISTEN_ADDR="127.0.0.1:18101" TOKEN_CACHE_SIZE=4096 LOG_LEVEL=error \
  "${BIN_CACHE}/gocloak-auth-proxy"

run_target "gocloak-auth-proxy (Go, Warm)" "reverse_proxy" "warm" 18102 "/readyz" "/api/items" \
  env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" UPSTREAM_URL="$UPSTREAM_URL" LISTEN_ADDR="127.0.0.1:18102" TOKEN_CACHE_SIZE=4096 LOG_LEVEL=error \
  "${BIN_CACHE}/gocloak-auth-proxy"

# 2. gocloak-auth-proxy (Cold - TOKEN_CACHE_SIZE=0, full crypto every request)
run_target "gocloak-auth-proxy (Go, Cold)" "forward_auth" "cold" 18103 "/readyz" "/auth" \
  env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" LISTEN_ADDR="127.0.0.1:18103" TOKEN_CACHE_SIZE=0 LOG_LEVEL=error \
  "${BIN_CACHE}/gocloak-auth-proxy"

run_target "gocloak-auth-proxy (Go, Cold)" "reverse_proxy" "cold" 18104 "/readyz" "/api/items" \
  env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" UPSTREAM_URL="$UPSTREAM_URL" LISTEN_ADDR="127.0.0.1:18104" TOKEN_CACHE_SIZE=0 LOG_LEVEL=error \
  "${BIN_CACHE}/gocloak-auth-proxy"

if [[ "$ONLY_GOCLOAK" == "1" ]]; then
  exit 0
fi

# 3. Go competitor: oauth2-proxy
if [[ -x "${BIN_CACHE}/oauth2-proxy" ]]; then
  run_target "oauth2-proxy v7.15.6 (Go)" "forward_auth" "warm" 18111 "/ping" "/oauth2/auth" \
    "${BIN_CACHE}/oauth2-proxy" \
      --provider=oidc \
      --oidc-issuer-url="$ISSUER" \
      --client-id="$AUDIENCE" \
      --client-secret="bench-secret" \
      --cookie-secret="12345678901234567890123456789012" \
      --skip-jwt-bearer-tokens=true \
      --extra-jwt-issuers="${ISSUER}=${AUDIENCE}" \
      --email-domain="*" \
      --http-address="127.0.0.1:18111" \
      --upstream="static://200" \
      --request-logging=false \
      --standard-logging=false \
      --auth-logging=false

  run_target "oauth2-proxy v7.15.6 (Go)" "reverse_proxy" "warm" 18112 "/ping" "/api/items" \
    "${BIN_CACHE}/oauth2-proxy" \
      --provider=oidc \
      --oidc-issuer-url="$ISSUER" \
      --client-id="$AUDIENCE" \
      --client-secret="bench-secret" \
      --cookie-secret="12345678901234567890123456789012" \
      --skip-jwt-bearer-tokens=true \
      --extra-jwt-issuers="${ISSUER}=${AUDIENCE}" \
      --email-domain="*" \
      --http-address="127.0.0.1:18112" \
      --upstream="$UPSTREAM_URL" \
      --request-logging=false \
      --standard-logging=false \
      --auth-logging=false
fi

# 4. Rust competitor: axum + tokio + jsonwebtoken
if [[ -x "${BIN_CACHE}/rust-auth-proxy" ]]; then
  run_target "rust-auth-proxy (Rust/Axum)" "forward_auth" "cold" 18121 "/healthz" "/auth" \
    env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" LISTEN_ADDR="127.0.0.1:18121" \
    "${BIN_CACHE}/rust-auth-proxy"

  run_target "rust-auth-proxy (Rust/Axum)" "reverse_proxy" "cold" 18122 "/healthz" "/api/items" \
    env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" UPSTREAM_URL="$UPSTREAM_URL" LISTEN_ADDR="127.0.0.1:18122" \
    "${BIN_CACHE}/rust-auth-proxy"
fi

# 5. Java 17 competitor: OpenJDK HttpServer + SHA256withRSA
if [[ -f "${BIN_CACHE}/java-proxy/AuthProxy.class" ]]; then
  run_target "java-auth-proxy (Java 17)" "forward_auth" "cold" 18131 "/healthz" "/auth" \
    env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" LISTEN_ADDR="127.0.0.1:18131" \
    java -XX:ActiveProcessorCount="${GOMAXPROCS}" -Xms64m -Xmx256m -cp "${BIN_CACHE}/java-proxy" AuthProxy

  run_target "java-auth-proxy (Java 17)" "reverse_proxy" "cold" 18132 "/healthz" "/api/items" \
    env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" UPSTREAM_URL="$UPSTREAM_URL" LISTEN_ADDR="127.0.0.1:18132" \
    java -XX:ActiveProcessorCount="${GOMAXPROCS}" -Xms64m -Xmx256m -cp "${BIN_CACHE}/java-proxy" AuthProxy
fi

# 6. Python competitor: Starlette + Uvicorn + PyJWT
if [[ -x "${BIN_CACHE}/py-venv/bin/uvicorn" ]]; then
  run_target "python-auth-proxy (Python/Uvicorn)" "forward_auth" "cold" 18141 "/healthz" "/auth" \
    env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" \
    "${BIN_CACHE}/py-venv/bin/uvicorn" --app-dir "${BENCH_DIR}/competitors/python-proxy" app:app \
      --host 127.0.0.1 --port 18141 --workers "${GOMAXPROCS}" --log-level error --no-access-log

  run_target "python-auth-proxy (Python/Uvicorn)" "reverse_proxy" "cold" 18142 "/healthz" "/api/items" \
    env ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" UPSTREAM_URL="$UPSTREAM_URL" \
    "${BIN_CACHE}/py-venv/bin/uvicorn" --app-dir "${BENCH_DIR}/competitors/python-proxy" app:app \
      --host 127.0.0.1 --port 18142 --workers "${GOMAXPROCS}" --log-level error --no-access-log
fi
