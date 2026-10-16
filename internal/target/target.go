// Package target parses raw input lines into normalized probe targets.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Scheme values. SchemeAuto means "decide by probing" (HTTPS/HTTP fallback).
const (
	SchemeAuto  = ""
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
	SchemeBoth  = "both" // probe both and report both (-no-fallback)
)

// Target is one normalized host to probe.
type Target struct {
	Input  string // original input text, reported verbatim in results
	Scheme string // SchemeAuto, SchemeHTTP or SchemeHTTPS
	Host   string // lower-case ASCII hostname or IP literal without brackets
	Port   int    // 0 means the default port of whichever scheme is probed
	Path   string // request URI from the input ("" = none given)
	Auth   string // "user:password" from the URL, sent as HTTP Basic auth
}

// Key returns the deduplication key for the target.
func (t Target) Key() string {
	return t.Scheme + "|" + t.Host + "|" + strconv.Itoa(t.Port) + "|" + t.Path
}

// IsIP reports whether Host is an IP literal.
func (t Target) IsIP() bool {
	_, err := netip.ParseAddr(t.Host)
	return err == nil
}

// ErrEmpty is returned for blank lines and comments.
var ErrEmpty = errors.New("empty input")

var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(false))

// Parse normalizes one input line. Accepted forms:
//
//	example.com  example.com:8443  example.com/admin  *.example.com
//	https://example.com:8443/path?q=1  192.0.2.1  [2001:db8::1]:8080
//
// CIDR ranges are handled by IsCIDR/ExpandCIDR, not here.
func Parse(raw string) (Target, error) {
	in := strings.TrimSpace(raw)
	if in == "" || strings.HasPrefix(in, "#") {
		return Target{}, ErrEmpty
	}
	t := Target{Input: in}
	// A bare IPv6 address ("::1", "2001:db8::1") has no brackets to tell
	// its colons from a port.
	if ip, err := netip.ParseAddr(in); err == nil {
		t.Host = ip.Unmap().String()
		return t, nil
	}

	s := in
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "http://"):
		t.Scheme = SchemeHTTP
	case strings.HasPrefix(lower, "https://"):
		t.Scheme = SchemeHTTPS
	case strings.Contains(s, "://"):
		return Target{}, fmt.Errorf("unsupported scheme in %q", in)
	default:
		s = "//" + s
	}
	// Wildcard prefixes (as produced by subdomain tools) probe the apex.
	if t.Scheme == SchemeAuto {
		rest := strings.TrimLeft(s[2:], "*.")
		s = "//" + rest
	}

	u, err := url.Parse(s)
	if err != nil {
		return Target{}, fmt.Errorf("invalid target %q: %w", in, err)
	}
	host := u.Hostname()
	if host == "" {
		return Target{}, fmt.Errorf("invalid target %q: missing host", in)
	}
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("invalid port in %q", in)
		}
		t.Port = port
	}
	h, err := normalizeHost(host)
	if err != nil {
		return Target{}, fmt.Errorf("invalid host in %q: %w", in, err)
	}
	t.Host = h
	if u.User != nil {
		t.Auth = u.User.Username()
		if p, ok := u.User.Password(); ok {
			t.Auth += ":" + p
		}
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" { // "/" is the default: same target
		t.Path = u.EscapedPath()
		if t.Path == "" {
			t.Path = "/"
		}
		if u.RawQuery != "" {
			t.Path += "?" + u.RawQuery
		}
	}
	return t, nil
}

func normalizeHost(host string) (string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), nil
	}
	host = strings.TrimSuffix(host, ".")
	if strings.ContainsAny(host, " \t/\\@") {
		return "", errors.New("illegal character")
	}
	ascii, err := idnaProfile.ToASCII(host)
	if err != nil {
		// Underscores and other technically-invalid labels are common in
		// recon data and still resolve; fall back to a plain lower-case form.
		ascii = host
	}
	if len(ascii) > 253 {
		return "", errors.New("name longer than 253 bytes")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return "", errors.New("empty or over-long (>63) label")
		}
	}
	return strings.ToLower(ascii), nil
}

// HostPort returns host:port with IPv6 brackets as needed.
func HostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// DefaultPort returns the well-known port for a scheme.
func DefaultPort(scheme string) int {
	if scheme == SchemeHTTPS {
		return 443
	}
	return 80
}

// BuildURL renders scheme://host[:port]path, omitting default ports.
func BuildURL(scheme, host string, port int, path string) string {
	var b strings.Builder
	b.Grow(len(scheme) + len(host) + len(path) + 12)
	b.WriteString(scheme)
	b.WriteString("://")
	if port == 0 || port == DefaultPort(scheme) {
		if strings.Contains(host, ":") {
			b.WriteByte('[')
			b.WriteString(host)
			b.WriteByte(']')
		} else {
			b.WriteString(host)
		}
	} else {
		b.WriteString(HostPort(host, port))
	}
	if path == "" {
		path = "/"
	} else if path[0] != '/' {
		b.WriteByte('/')
	}
	b.WriteString(path)
	return b.String()
}
