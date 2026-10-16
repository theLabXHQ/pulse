package extract

import (
	"net/http"
	"net/netip"
	"strings"
)

// CSPHosts returns the hostnames named by host-source expressions in the
// Content-Security-Policy headers (enforced and report-only). Keywords
// ('self'), nonces/hashes, scheme sources (https:, data:) and bare "*" are
// ignored; a wildcard "*.example.com" yields "example.com". The result is
// lower-cased, deduplicated and in first-seen order.
func CSPHosts(h http.Header) []string {
	var out []string
	seen := map[string]bool{}
	for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		for _, policy := range h.Values(name) {
			for _, directive := range strings.Split(policy, ";") {
				fields := strings.Fields(directive)
				if len(fields) < 2 {
					continue
				}
				for _, src := range fields[1:] { // fields[0] is the directive name
					if host := cspSourceHost(src); host != "" && !seen[host] {
						seen[host] = true
						out = append(out, host)
					}
				}
			}
		}
	}
	return out
}

// cspSourceHost extracts the host of one source expression, or "".
func cspSourceHost(src string) string {
	if strings.HasPrefix(src, "'") || strings.HasSuffix(src, ":") {
		return "" // keyword, nonce/hash, or scheme-source
	}
	src = strings.ToLower(src)
	if i := strings.Index(src, "://"); i >= 0 {
		src = src[i+3:]
	}
	if i := strings.IndexAny(src, "/?#"); i >= 0 {
		src = src[:i]
	}
	if strings.HasPrefix(src, "[") { // [v6]:port
		if i := strings.Index(src, "]"); i > 0 {
			if ip, err := netip.ParseAddr(src[1:i]); err == nil {
				return ip.String()
			}
		}
		return ""
	}
	if i := strings.LastIndexByte(src, ':'); i >= 0 {
		src = src[:i]
	}
	src = strings.TrimPrefix(src, "*.")
	src = strings.TrimSuffix(src, ".")
	if !ValidHostname(src) {
		return ""
	}
	return src
}

// ValidHostname reports whether s is a plausible DNS name with at least two
// labels (or an IP address): letters, digits and hyphens, labels of 1-63
// bytes not starting or ending with a hyphen.
func ValidHostname(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
