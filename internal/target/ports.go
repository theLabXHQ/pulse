package target

import (
	"fmt"
	"strconv"
	"strings"
)

// PortSpec is one port to probe with an optional forced scheme.
type PortSpec struct {
	Port   int
	Scheme string // SchemeAuto, SchemeHTTP or SchemeHTTPS
}

// ParsePorts parses nmap-like port lists:
//
//	80,443,8000-8010,http:8080,https:8443,https:9000-9002
//
// A scheme prefix applies to the item it is attached to. Duplicates keep the
// first occurrence. Order is preserved, which keeps output deterministic.
func ParsePorts(spec string) ([]PortSpec, error) {
	var out []PortSpec
	seen := map[PortSpec]bool{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		scheme := SchemeAuto
		if i := strings.IndexByte(item, ':'); i >= 0 {
			switch strings.ToLower(item[:i]) {
			case "http":
				scheme = SchemeHTTP
			case "https":
				scheme = SchemeHTTPS
			default:
				return nil, fmt.Errorf("unknown scheme %q in port spec", item[:i])
			}
			item = item[i+1:]
		}
		lo, hi, err := parseRange(item)
		if err != nil {
			return nil, err
		}
		for p := lo; p <= hi; p++ {
			ps := PortSpec{Port: p, Scheme: scheme}
			if !seen[ps] {
				seen[ps] = true
				out = append(out, ps)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty port list")
	}
	return out, nil
}

func parseRange(s string) (int, int, error) {
	a, b, isRange := strings.Cut(s, "-")
	lo, err := parsePort(a)
	if err != nil {
		return 0, 0, err
	}
	if !isRange {
		return lo, lo, nil
	}
	hi, err := parsePort(b)
	if err != nil {
		return 0, 0, err
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	return lo, hi, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}

// commonHTTPPorts are ports where plaintext HTTP is far more likely than TLS.
var commonHTTPPorts = map[int]bool{80: true, 8000: true, 8008: true, 8080: true, 8081: true, 8888: true, 3000: true, 5000: true, 9000: true}

// SchemeOrder decides which scheme to try first when the scheme is unknown.
// HTTPS first on 443, on ports ending in 443 (4443, 8443, 9443, 10443, ...,
// conventionally TLS) and on unspecified ports (the common internet case);
// HTTP first on well-known plaintext ports and on other ports above 1024,
// which on the public internet are mostly plaintext services. A wrong guess
// costs one extra request, so the guess is worth getting right.
func SchemeOrder(port int) [2]string {
	switch {
	case port == 0 || port%1000 == 443:
		return [2]string{SchemeHTTPS, SchemeHTTP}
	case commonHTTPPorts[port] || port > 1024:
		return [2]string{SchemeHTTP, SchemeHTTPS}
	default:
		return [2]string{SchemeHTTPS, SchemeHTTP}
	}
}
