#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${PPROF_DIR:-/tmp/gocloak-pprof}"
BENCHTIME="${BENCHTIME:-2s}"
mkdir -p "$OUT_DIR"

echo "==> Capturing CPU & memory profiles into ${OUT_DIR} (benchtime=${BENCHTIME})..."
go test -run '^$' -bench 'BenchmarkVerify/RS256' -benchmem -benchtime="$BENCHTIME" \
  -cpuprofile="${OUT_DIR}/auth_rs256_cpu.out" -memprofile="${OUT_DIR}/auth_rs256_mem.out" ./internal/auth
go test -run '^$' -bench 'BenchmarkVerifyCached' -benchmem -benchtime="$BENCHTIME" \
  -cpuprofile="${OUT_DIR}/auth_cached_cpu.out" -memprofile="${OUT_DIR}/auth_cached_mem.out" ./internal/auth
go test -run '^$' -bench 'BenchmarkForwardAuth' -benchmem -benchtime="$BENCHTIME" \
  -cpuprofile="${OUT_DIR}/proxy_cpu.out" -memprofile="${OUT_DIR}/proxy_mem.out" ./internal/proxy
go test -run '^$' -bench 'BenchmarkReadSession' -benchmem -benchtime="$BENCHTIME" \
  -cpuprofile="${OUT_DIR}/oidc_cpu.out" -memprofile="${OUT_DIR}/oidc_mem.out" ./internal/oidc

echo ""
echo "=== Top CPU: auth RS256 (Cold) ==="
go tool pprof -top -cum -nodecount=15 "${OUT_DIR}/auth_rs256_cpu.out"
echo ""
echo "=== Top Allocs: auth RS256 (Cold) ==="
go tool pprof -top -alloc_objects -nodecount=15 "${OUT_DIR}/auth_rs256_mem.out"
echo ""
echo "=== Top CPU: proxy ForwardAuth ==="
go tool pprof -top -cum -nodecount=15 "${OUT_DIR}/proxy_cpu.out"
echo ""
echo "=== Top CPU: oidc ReadSession ==="
go tool pprof -top -cum -nodecount=15 "${OUT_DIR}/oidc_cpu.out"
