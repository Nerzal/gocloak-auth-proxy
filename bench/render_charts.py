#!/usr/bin/env python3
"""Render GitHub-friendly dark-theme SVG benchmark charts for README.md."""

from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "docs" / "assets"

BG = "#0d1117"
CARD = "#161b22"
BORDER = "#30363d"
TRACK = "#21262d"
TEXT = "#e6edf3"
MUTED = "#8b949e"

ACCENT = "#22c55e"      # gocloak-auth-proxy (Warm / primary highlight)
ACCENT_2 = "#38bdf8"    # gocloak-auth-proxy (Cold / secondary highlight)
COMP_RUST = "#f97316"   # Rust Axum
COMP_GO = "#58a6ff"     # oauth2-proxy (Go)
COMP_JAVA = "#ef4444"   # Java 17
COMP_PY = "#a78bfa"     # Python 3.11


def fmt_num(val: float, suffix: str = "") -> str:
    if val == 0:
        return f"0{suffix}"
    if val >= 1000:
        return f"{val:,.0f}{suffix}"
    if val >= 100:
        return f"{val:.0f}{suffix}"
    return f"{val:.1f}{suffix}"


def render_bar_panel(
    x: int,
    y: int,
    w: int,
    h: int,
    title: str,
    subtitle: str,
    items: list[tuple[str, float, str, bool]],
    suffix: str,
    max_val: float | None = None,
) -> str:
    parts = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{CARD}" stroke="{BORDER}" stroke-width="1"/>',
        f'<text x="{x + 20}" y="{y + 30}" fill="{TEXT}" font-size="15" font-weight="700">{escape(title)}</text>',
        f'<text x="{x + 20}" y="{y + 48}" fill="{MUTED}" font-size="11.5">{escape(subtitle)}</text>',
    ]
    top_max = max_val if max_val is not None else max(v for _, v, _, _ in items)
    bar_x = x + 195
    bar_max_w = w - 295
    row_y = y + 72
    row_step = (h - 86) / max(len(items), 1)

    for label, value, color, highlight in items:
        bw = 4.0 if value == 0 else max(6.0, (value / top_max) * bar_max_w)
        font_w = "700" if highlight else "500"
        label_fill = color if highlight else TEXT
        val_fill = color if highlight else TEXT
        cy = row_y + 11

        parts.append(
            f'<text x="{bar_x - 12}" y="{cy + 4}" text-anchor="end" fill="{label_fill}" '
            f'font-size="11.5" font-weight="{font_w}">{escape(label)}</text>'
        )
        parts.append(
            f'<rect x="{bar_x}" y="{row_y}" width="{bar_max_w:.1f}" height="18" rx="5" fill="{TRACK}"/>'
        )
        parts.append(
            f'<rect x="{bar_x}" y="{row_y}" width="{bw:.1f}" height="18" rx="5" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{bar_x + bw + 8:.1f}" y="{cy + 4}" fill="{val_fill}" '
            f'font-size="11.5" font-weight="{font_w}">{escape(fmt_num(value, suffix))}</text>'
        )
        row_y += row_step

    return "\n  ".join(parts)


def build_overview_svg() -> str:
    w, h = 1120, 680
    pw, ph = 528, 266
    gap = 20
    left_x = 22
    right_x = left_x + pw + gap
    top_y = 78
    bot_y = top_y + ph + gap

    fwd_rps = [
        ("gocloak-auth-proxy (Warm)", 25169, ACCENT, True),
        ("Rust Axum (Cold)", 21616, COMP_RUST, False),
        ("gocloak-auth-proxy (Cold)", 15002, ACCENT_2, True),
        ("Java 17 (Cold)", 6839, COMP_JAVA, False),
        ("oauth2-proxy v7.15 (Warm)", 6023, COMP_GO, False),
        ("Python Uvicorn (Cold)", 5811, COMP_PY, False),
    ]
    rev_rps = [
        ("gocloak-auth-proxy (Warm)", 11248, ACCENT, True),
        ("Rust Axum (Cold)", 10629, COMP_RUST, False),
        ("gocloak-auth-proxy (Cold)", 7583, ACCENT_2, True),
        ("oauth2-proxy v7.15 (Warm)", 2245, COMP_GO, False),
        ("Java 17 (Cold)", 1978, COMP_JAVA, False),
        ("Python Uvicorn (Cold)", 734, COMP_PY, False),
    ]
    rev_p50 = [
        ("gocloak-auth-proxy (Warm)", 2.51, ACCENT, True),
        ("Rust Axum (Cold)", 2.86, COMP_RUST, False),
        ("gocloak-auth-proxy (Cold)", 3.90, ACCENT_2, True),
        ("oauth2-proxy v7.15 (Warm)", 13.39, COMP_GO, False),
        ("Java 17 (Cold)", 14.23, COMP_JAVA, False),
        ("Python Uvicorn (Cold)", 32.95, COMP_PY, False),
    ]
    rss_load = [
        ("Rust Axum", 6.3, COMP_RUST, False),
        ("gocloak-auth-proxy (Warm)", 16.1, ACCENT, True),
        ("gocloak-auth-proxy (Cold)", 16.2, ACCENT_2, True),
        ("oauth2-proxy v7.15", 27.8, COMP_GO, False),
        ("Java 17", 114.4, COMP_JAVA, False),
    ]

    p1 = render_bar_panel(
        left_x, top_y, pw, ph,
        "Forward-Auth Throughput (req/s)",
        "Higher is better · C=32 · RS256 2048-bit JWT · 0 errors",
        fwd_rps, " req/s", max_val=27000,
    )
    p2 = render_bar_panel(
        right_x, top_y, pw, ph,
        "Reverse-Proxy Throughput (req/s)",
        "Higher is better · C=32 · RS256 2048-bit JWT · 0 errors",
        rev_rps, " req/s", max_val=12000,
    )
    p3 = render_bar_panel(
        left_x, bot_y, pw, ph,
        "Reverse-Proxy Median Latency (p50 ms)",
        "Lower is better · 5.3x lower than oauth2-proxy",
        rev_p50, " ms", max_val=36,
    )
    p4 = render_bar_panel(
        right_x, bot_y, pw, ph,
        "Memory Under Load (Reverse-Proxy MB RSS)",
        "Lower is better · Idle RSS: gocloak-auth-proxy 9.2 MB",
        rss_load, " MB", max_val=120,
    )

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="gocloak-auth-proxy Head-to-Head Cross-Language Benchmarks">
  <defs>
    <style>
      text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    </style>
  </defs>
  <rect width="{w}" height="{h}" rx="16" fill="{BG}" stroke="{BORDER}" stroke-width="1"/>
  <text x="24" y="36" fill="{TEXT}" font-size="20" font-weight="800">gocloak-auth-proxy — Cross-Language Keycloak Auth Proxy Benchmarks</text>
  <text x="24" y="57" fill="{MUTED}" font-size="12.5">Intel Xeon 6985P-C (GOMAXPROCS=2, C=32, D=5s) · RS256 2048-bit JWT · Go 1.27.4 + gocloak v15.1.0 (SetDirectBodyRead)</text>
  <rect x="{w - 252}" y="20" width="228" height="30" rx="15" fill="#0d2b24" stroke="{ACCENT}" stroke-width="1"/>
  <text x="{w - 138}" y="39" text-anchor="middle" fill="{ACCENT}" font-size="12" font-weight="700">#1 Forward-Auth &amp; Reverse-Proxy</text>
  {p1}
  {p2}
  {p3}
  {p4}
  <text x="24" y="{h - 14}" fill="{MUTED}" font-size="11">Container Image: ~11.3 MB (distroless nonroot) · Binary: 8.9 MB (CGO_ENABLED=0) · Reproducible via make bench-compare &amp; make bench-keycloak</text>
</svg>
'''


def build_pprof_svg() -> str:
    w, h = 1120, 360
    pw, ph = 528, 246
    left_x = 22
    right_x = left_x + pw + 20
    top_y = 78

    mem_bytes = [
        ("Baseline EdDSA + Claims", 8540, "#6e7681", False),
        ("Baseline RS256 (v0.1.0)", 6412, "#8b949e", False),
        ("jsontext JWS RS256 (Cold)", 1728, ACCENT_2, True),
        ("jsontext EdDSA + Claims", 624, ACCENT_2, True),
        ("Verified-Token Cache", 0, ACCENT, True),
    ]
    allocs = [
        ("Baseline EdDSA + Claims", 104, "#6e7681", False),
        ("Baseline RS256 (v0.1.0)", 79, "#8b949e", False),
        ("jsontext JWS RS256 (Cold)", 33, ACCENT_2, True),
        ("jsontext EdDSA + Claims", 24, ACCENT_2, True),
        ("Verified-Token Cache", 0, ACCENT, True),
    ]

    p1 = render_bar_panel(
        left_x, top_y, pw, ph,
        "JWT Verification Memory (B/op)",
        "Lower is better · -73% RS256 Cold · -93% EdDSA + Custom Claims",
        mem_bytes, " B", max_val=9000,
    )
    p2 = render_bar_panel(
        right_x, top_y, pw, ph,
        "Heap Allocations per Verify (allocs/op)",
        "Lower is better · -58% RS256 Cold · -77% EdDSA · 0 allocs Warm",
        allocs, " allocs", max_val=110,
    )

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="gocloak-auth-proxy pprof Optimization Progression">
  <defs>
    <style>
      text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    </style>
  </defs>
  <rect width="{w}" height="{h}" rx="16" fill="{BG}" stroke="{BORDER}" stroke-width="1"/>
  <text x="24" y="36" fill="{TEXT}" font-size="20" font-weight="800">pprof-Driven Optimization Impact (v0.1.0 → v0.2.0)</text>
  <text x="24" y="57" fill="{MUTED}" font-size="12.5">Zero-map jsontext/jsonv2 JWS verifier + key-rotation-safe sharded token cache (463 ns/op, 0 allocs) · OIDC ReadSession -40% latency</text>
  {p1}
  {p2}
  <text x="24" y="{h - 14}" fill="{MUTED}" font-size="11">Reproduce profiles locally: make bench-profile (CPU &amp; memory pprof for internal/auth, internal/proxy, internal/oidc)</text>
</svg>
'''


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "benchmark-overview.svg").write_text(build_overview_svg(), encoding="utf-8")
    (OUT_DIR / "pprof-progression.svg").write_text(build_pprof_svg(), encoding="utf-8")
    print(f"Generated SVGs in {OUT_DIR}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
