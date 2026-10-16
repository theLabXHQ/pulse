package engine

import (
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"

	"github.com/theLabXHQ/pulse/internal/extract"
	"github.com/theLabXHQ/pulse/internal/probe"
)

// DiscoverConfig enables probing hostnames found in responses (-tls-probe,
// -csp-probe).
//
// Discovery is bounded: by default only names under the same
// registrable domain as the response's host are followed (a shared CDN
// certificate must not pull the scan out of scope), recursion stops at
// MaxDepth, and at most MaxTargets names are queued in total.
type DiscoverConfig struct {
	TLS, CSP   bool
	AnyScope   bool // follow names under any domain (default: same eTLD+1)
	MaxDepth   int  // 1 = names found on input targets only
	MaxTargets int
}

type discovery struct {
	host  string
	line  int64 // the input line it is accounted to (resume)
	depth int
	via   string // "tls:<host>" or "csp:<host>"
}

// discoverer queues discovered names for the dispatcher. Workers never
// block on it; it is bounded by MaxTargets unique names.
type discoverer struct {
	cfg   DiscoverConfig
	mu    sync.Mutex
	queue []discovery
	seen  map[string]struct{}
	wake  chan struct{} // capacity 1: "queue changed or a task finished"
}

func newDiscoverer(cfg DiscoverConfig) *discoverer {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 1
	}
	if cfg.MaxTargets <= 0 {
		cfg.MaxTargets = 10000
	}
	return &discoverer{cfg: cfg, seen: make(map[string]struct{}), wake: make(chan struct{}, 1)}
}

func (d *discoverer) signal() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// push queues host unless it was seen or the budget is spent.
func (d *discoverer) push(x discovery) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, dup := d.seen[x.host]; dup || len(d.seen) >= d.cfg.MaxTargets {
		return false
	}
	d.seen[x.host] = struct{}{}
	d.queue = append(d.queue, x)
	return true
}

func (d *discoverer) drain() []discovery {
	d.mu.Lock()
	defer d.mu.Unlock()
	q := d.queue
	d.queue = nil
	return q
}

func (d *discoverer) empty() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.queue) == 0
}

// discover queues the names a successful response reveals. It runs on a
// worker before the task finishes, so the task's input line stays open
// (resume) until every queued name has been dispatched.
func (e *Engine) discover(t *task, r *probe.Response) {
	d := e.disc
	if d == nil || t.depth >= d.cfg.MaxDepth {
		return
	}
	src := strings.ToLower(t.spec.Host)
	add := func(name, kind string) {
		name = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(name), "."), "*.")
		if name == src || !extract.ValidHostname(name) || !d.inScope(src, name) {
			return
		}
		if d.push(discovery{host: name, line: t.line, depth: t.depth + 1, via: kind + ":" + src}) {
			e.track.add(t.line)
			e.Stats.Discovered.Add(1)
			d.signal()
		}
	}
	if d.cfg.TLS && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		for _, n := range cert.DNSNames {
			add(n, "tls")
		}
		add(cert.Subject.CommonName, "tls")
	}
	if d.cfg.CSP {
		for _, n := range extract.CSPHosts(r.Header) {
			add(n, "csp")
		}
	}
}

// inScope reports whether name may be probed when found on src.
func (d *discoverer) inScope(src, name string) bool {
	if d.cfg.AnyScope {
		return true
	}
	if isIP(src) || isIP(name) {
		return false // no registrable domain to compare
	}
	a, err1 := publicsuffix.EffectiveTLDPlusOne(src)
	b, err2 := publicsuffix.EffectiveTLDPlusOne(name)
	return err1 == nil && err2 == nil && a == b
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}
