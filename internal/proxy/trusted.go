package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// trustedProxySet holds parsed CIDR prefixes permitted to supply X-Forwarded-* headers.
type trustedProxySet struct {
	prefixes []netip.Prefix
}

func parseTrustedProxies(entries []string) (*trustedProxySet, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", raw, err)
			}
			prefixes = append(prefixes, p.Masked())
		} else {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy IP %q: %w", raw, err)
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
		}
	}
	if len(prefixes) == 0 {
		return nil, nil
	}
	return &trustedProxySet{prefixes: prefixes}, nil
}

func (t *trustedProxySet) isTrusted(remoteAddr string) (netip.Addr, bool) {
	if t == nil || len(t.prefixes) == 0 || remoteAddr == "" {
		return netip.Addr{}, false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return addr, true
		}
	}
	return addr, false
}

type forwardedMeta struct {
	xff   string
	proto string
	host  string
}

func extractTrustedForwarded(r *http.Request, trusted *trustedProxySet) (forwardedMeta, bool) {
	addr, ok := trusted.isTrusted(r.RemoteAddr)
	if !ok {
		return forwardedMeta{}, false
	}
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" && validValue(xff) {
		xff = xff + ", " + addr.String()
	} else {
		xff = addr.String()
	}
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if proto != "http" && proto != "https" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host != "" && !validValue(host) {
		host = ""
	}
	return forwardedMeta{xff: xff, proto: proto, host: host}, true
}
