package probe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"sync"
	"time"
)

// Timing reports per-phase durations in milliseconds for the final hop of a
// probe. Phases that did not happen (e.g. DNS for an IP literal, connect on a
// reused connection) are zero. Total covers the whole probe: every scheme
// attempt, retry and redirect hop, including reading the body.
type Timing struct {
	DNS     float64 `json:"dns_ms"`
	Connect float64 `json:"connect_ms"`
	TLS     float64 `json:"tls_ms"`
	TTFB    float64 `json:"ttfb_ms"` // request start -> first response byte
	Total   float64 `json:"total_ms"`
}

type traceState struct {
	dnsDone, connectStarted, connectDone bool
	tlsStarted, tlsDone, wroteRequest    bool
	firstByte                            bool
}

func (s traceState) phase() Phase {
	switch {
	case !s.connectDone:
		return PhaseConnect
	case s.tlsStarted && !s.tlsDone:
		return PhaseTLS
	case !s.wroteRequest:
		return PhaseRequest
	default:
		return PhaseResponse
	}
}

// attemptTrace records the progress of one HTTP round trip. Callbacks may run
// on transport goroutines (a dial can outlive the request that started it),
// hence the mutex.
type attemptTrace struct {
	mu                 sync.Mutex
	start              time.Time
	dnsStart, dnsEnd   time.Time
	connStart, connEnd time.Time
	tlsStart, tlsEnd   time.Time
	firstByte          time.Time
	st                 traceState
	reused             bool
	remoteIP           string
	tlsState           *tls.ConnectionState
	lastConnectErr     error
}

type traceKey struct{}

func newAttemptTrace() *attemptTrace { return &attemptTrace{start: time.Now()} }

func traceFrom(ctx context.Context) *attemptTrace {
	t, _ := ctx.Value(traceKey{}).(*attemptTrace)
	return t
}

func (t *attemptTrace) snapshot() traceState {
	if t == nil {
		return traceState{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.st
}

func (t *attemptTrace) markDNS(start, end time.Time) {
	t.mu.Lock()
	t.dnsStart, t.dnsEnd = start, end
	t.st.dnsDone = true
	t.mu.Unlock()
}

// with attaches the trace to ctx both as a value (read by our dialer) and as
// an httptrace.ClientTrace (fed by net/http and the net package).
func (t *attemptTrace) with(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, traceKey{}, t)
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			t.mu.Lock()
			if !t.st.connectStarted {
				t.connStart = time.Now()
			}
			t.st.connectStarted = true
			t.mu.Unlock()
		},
		ConnectDone: func(_, addr string, err error) {
			t.mu.Lock()
			if err == nil {
				if !t.st.connectDone { // a raced dial that lost connects later
					t.connEnd = time.Now()
				}
				t.st.connectDone = true
			} else {
				t.lastConnectErr = err
			}
			t.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			t.tlsStart = time.Now()
			t.st.tlsStarted = true
			t.mu.Unlock()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			t.mu.Lock()
			if err == nil {
				t.tlsEnd = time.Now()
				t.st.tlsDone = true
				t.tlsState = &cs
			}
			t.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			t.reused = info.Reused
			if info.Reused {
				// A pooled connection skipped DNS, connect and TLS.
				t.st.dnsDone, t.st.connectStarted, t.st.connectDone = true, true, true
				if t.st.tlsStarted {
					t.st.tlsDone = true
				}
			}
			if info.Conn != nil {
				if a, ok := info.Conn.RemoteAddr().(*net.TCPAddr); ok {
					t.remoteIP = a.IP.String()
				}
			}
			t.mu.Unlock()
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			t.mu.Lock()
			t.st.wroteRequest = true
			t.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			t.firstByte = time.Now()
			t.st.firstByte = true
			t.mu.Unlock()
		},
	})
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func span(a, b time.Time) float64 {
	if a.IsZero() || b.IsZero() || b.Before(a) {
		return 0
	}
	return ms(b.Sub(a))
}

func (t *attemptTrace) timing() Timing {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Timing{
		DNS:     span(t.dnsStart, t.dnsEnd),
		Connect: span(t.connStart, t.connEnd),
		TLS:     span(t.tlsStart, t.tlsEnd),
		TTFB:    span(t.start, t.firstByte),
	}
}
