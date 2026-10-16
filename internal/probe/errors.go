package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"syscall"
)

// Class is a stable, machine-readable failure category. Values are part of
// the JSONL schema; add new ones rather than renaming existing ones.
type Class string

const (
	ClassDNSNotFound    Class = "dns_nxdomain"
	ClassDNSTimeout     Class = "dns_timeout"
	ClassDNSError       Class = "dns_error"
	ClassConnRefused    Class = "conn_refused"
	ClassConnTimeout    Class = "conn_timeout"
	ClassConnReset      Class = "conn_reset"
	ClassConnClosed     Class = "conn_closed" // peer closed before sending a response
	ClassUnreachable    Class = "net_unreachable"
	ClassTLSHandshake   Class = "tls_handshake"
	ClassTLSTimeout     Class = "tls_timeout"
	ClassPlainOnTLS     Class = "tls_plaintext_response" // HTTPS attempt answered with plaintext HTTP
	ClassResponseTimout Class = "response_timeout"       // connected, request sent, no response headers in time
	ClassProtocol       Class = "protocol_error"
	ClassRedirectLoop   Class = "redirect_loop"
	ClassTooManyRedirs  Class = "too_many_redirects"
	ClassPolicy         Class = "policy_denied"
	ClassHostSkipped    Class = "host_skipped"
	ClassCDNPortSkipped Class = "cdn_port_skipped" // -ec: non-80/443 port of a CDN/WAF address
	ClassProxy          Class = "proxy_error"
	ClassCanceled       Class = "canceled"
	ClassInvalid        Class = "invalid_request"
	ClassOther          Class = "other"
)

// Phase is the request phase in which a failure happened.
type Phase string

const (
	PhaseDNS      Phase = "dns"
	PhaseConnect  Phase = "connect"
	PhaseTLS      Phase = "tls"
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
	PhaseRedirect Phase = "redirect"
	PhasePolicy   Phase = "policy"
)

// Error is a classified probe failure.
type Error struct {
	Class Class
	Phase Phase
	Err   error
}

func (e *Error) Error() string { return string(e.Class) + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// ConnectionLevel reports whether the failure says nothing about HTTP vs
// HTTPS (the TCP endpoint itself is unusable). Retrying the other scheme on
// the same host:port cannot succeed after such errors.
func (e *Error) ConnectionLevel() bool {
	switch e.Class {
	case ClassConnRefused, ClassConnTimeout, ClassUnreachable, ClassDNSNotFound,
		ClassDNSTimeout, ClassDNSError, ClassPolicy, ClassProxy, ClassCanceled, ClassHostSkipped,
		ClassCDNPortSkipped:
		return true
	}
	return false
}

// HostLevel reports whether the failure applies to every port of the host
// (name resolution or policy), so no other port or scheme should be tried.
func (e *Error) HostLevel() bool {
	switch e.Class {
	case ClassDNSNotFound, ClassDNSTimeout, ClassDNSError, ClassPolicy, ClassCanceled:
		return true
	}
	return false
}

// Transient reports whether an identical retry may plausibly succeed.
func (e *Error) Transient() bool {
	switch e.Class {
	case ClassConnReset, ClassConnClosed, ClassConnTimeout, ClassTLSTimeout, ClassResponseTimout, ClassDNSTimeout:
		return true
	}
	return false
}

// errPolicy marks dials refused by the network policy.
type errPolicy struct{ ip string }

func (e errPolicy) Error() string { return "address " + e.ip + " denied by network policy" }

// classify maps an error to a Class using the phase progress recorded for
// the attempt, which disambiguates the many errors Go reports as timeouts.
func classify(err error, tr *attemptTrace, proxied bool) *Error {
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	st := tr.snapshot()
	mk := func(c Class, p Phase) *Error { return &Error{Class: c, Phase: p, Err: err} }

	var pol errPolicy
	if errors.As(err, &pol) {
		return mk(ClassPolicy, PhasePolicy)
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && !st.connectStarted {
		switch {
		case dnsErr.IsNotFound:
			return mk(ClassDNSNotFound, PhaseDNS)
		case dnsErr.IsTimeout:
			return mk(ClassDNSTimeout, PhaseDNS)
		default:
			return mk(ClassDNSError, PhaseDNS)
		}
	}
	if errors.Is(err, context.Canceled) {
		return mk(ClassCanceled, st.phase())
	}

	msg := err.Error()
	if strings.Contains(msg, "server gave HTTP response to HTTPS client") {
		return mk(ClassPlainOnTLS, PhaseTLS)
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		if strings.HasPrefix(string(rhe.RecordHeader[:]), "HTTP/") {
			return mk(ClassPlainOnTLS, PhaseTLS)
		}
		return mk(ClassTLSHandshake, PhaseTLS)
	}
	if proxied && (strings.Contains(msg, "proxyconnect") || strings.Contains(msg, "socks connect")) {
		return mk(ClassProxy, PhaseConnect)
	}

	timeout := errors.Is(err, context.DeadlineExceeded) || errnoIn(err, errnoTimedOut)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		timeout = true
	}
	if timeout {
		switch {
		case !st.dnsDone && !st.connectStarted:
			return mk(ClassDNSTimeout, PhaseDNS)
		case !st.connectDone:
			return mk(ClassConnTimeout, PhaseConnect)
		case st.tlsStarted && !st.tlsDone:
			return mk(ClassTLSTimeout, PhaseTLS)
		default:
			return mk(ClassResponseTimout, PhaseResponse)
		}
	}

	switch {
	case errnoIn(err, errnoRefused):
		return mk(ClassConnRefused, PhaseConnect)
	case errnoIn(err, errnoUnreachable):
		return mk(ClassUnreachable, PhaseConnect)
	case errnoIn(err, errnoReset):
		return mk(ClassConnReset, st.phase())
	}
	if st.tlsStarted && !st.tlsDone {
		return mk(ClassTLSHandshake, PhaseTLS)
	}
	var alert tls.AlertError
	if errors.As(err, &alert) || strings.HasPrefix(msg, "tls:") || strings.Contains(msg, ": tls:") {
		return mk(ClassTLSHandshake, PhaseTLS)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return mk(ClassConnClosed, st.phase())
	}
	if strings.Contains(msg, "malformed HTTP") || strings.Contains(msg, "invalid") && st.wroteRequest {
		return mk(ClassProtocol, PhaseResponse)
	}
	if !st.connectDone {
		return mk(ClassOther, PhaseConnect)
	}
	return mk(ClassOther, st.phase())
}

// errnoIn reports whether err wraps one of the platform's errno values.
func errnoIn(err error, list []syscall.Errno) bool {
	var e syscall.Errno
	return errors.As(err, &e) && slices.Contains(list, e)
}
