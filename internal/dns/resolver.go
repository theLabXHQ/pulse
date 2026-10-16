// Package dns resolves hostnames with a bounded, TTL-limited cache and
// request coalescing, so that many probes against the same host (ports x
// paths x schemes) trigger exactly one lookup.
package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theLabXHQ/pulse/internal/lru"
)

// Resolver looks up the addresses of a host. Implementations must be safe for
// concurrent use. Returned errors for missing names should be *net.DNSError
// with IsNotFound set so callers can classify them.
type Resolver interface {
	Lookup(ctx context.Context, host string) ([]netip.Addr, error)
}

// Options configures a CachingResolver.
type Options struct {
	// Servers are "ip" or "ip:port" DNS servers. Empty means the system resolver.
	Servers []string
	// CacheSize bounds the number of cached hostnames.
	CacheSize int
	// TTL is how long positive answers are reused. Go's resolver does not
	// expose record TTLs, so this is a fixed upper bound.
	TTL time.Duration
	// NegativeTTL is how long failures (NXDOMAIN, SERVFAIL, timeouts) are reused.
	NegativeTTL time.Duration
	// Timeout bounds a single lookup, independent of the caller's deadline.
	Timeout time.Duration
	// PreferIPv6 orders AAAA answers before A answers.
	PreferIPv6 bool
	// Fallback servers ("ip[:port]") back up the system resolver (Servers
	// empty): a name the system resolver does not answer within
	// systemTryTimeout is asked there instead, and after fallbackAfter
	// consecutive timeouts (or a failed CheckSystem) every lookup goes
	// there. Empty = never leave the system resolver. OnFallback, if set, is
	// called once on the switch.
	Fallback   []string
	OnFallback func(reason string)
	// ResolvConf and HostsFile describe the system resolver (defaults
	// /etc/resolv.conf, /etc/hosts). If resolv.conf names servers, the
	// system resolver runs over Pulse's UDP client; otherwise Go's.
	ResolvConf, HostsFile string
	// AutoCheck runs CheckSystem in the background on the first lookup of a
	// name (never for runs that only probe IP addresses).
	AutoCheck bool
}

// fallbackAfter consecutive system-resolver timeouts switch to Fallback.
const fallbackAfter = 20

// systemTryTimeout bounds a system lookup when a fallback can answer instead.
const systemTryTimeout = 2 * time.Second

type cached struct {
	addrs      []netip.Addr
	err        error
	expires    time.Time
	sysTimeout bool // a system-resolver timeout: ignored once on fallback
}

type call struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// CachingResolver implements Resolver on top of net.Resolver.
type CachingResolver struct {
	opts  Options
	net   *net.Resolver
	udp   *udpClient      // explicit servers (-r); nil = system resolver
	sys   *systemResolver // system resolver over UDP; nil = Go's resolver
	cache *lru.Cache[string, cached]

	mu       sync.Mutex
	inflight map[string]*call

	lookups atomic.Int64 // number of real (uncached) lookups, for stats
	now     func() time.Time

	fb       *udpClient    // fallback servers, nil if none
	fbNet    *net.Resolver // fallback for truncated answers (TCP)
	useFB    atomic.Bool
	timeouts atomic.Int64 // consecutive system-resolver timeouts

	hosts     map[string][]netip.Addr // hosts file, honoured on the fallback too
	checkOnce sync.Once
}

// New creates a caching resolver.
func New(opts Options) *CachingResolver {
	if opts.CacheSize <= 0 {
		opts.CacheSize = 65536
	}
	if opts.TTL <= 0 {
		opts.TTL = 5 * time.Minute
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = 30 * time.Second
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	r := &CachingResolver{
		opts:     opts,
		cache:    lru.New[string, cached](opts.CacheSize),
		inflight: make(map[string]*call),
		now:      time.Now,
	}
	r.net = newNetResolver(opts.Servers)
	if servers := parseServers(opts.Servers); len(servers) > 0 {
		// A socket failure here only costs the fast path; net.Resolver still works.
		r.udp, _ = newUDPClient(servers, opts.PreferIPv6, r.net)
	}
	if len(opts.Servers) == 0 {
		if opts.ResolvConf == "" {
			opts.ResolvConf = "/etc/resolv.conf"
		}
		if opts.HostsFile == "" {
			opts.HostsFile = defaultHostsFile()
		}
		r.hosts = loadHosts(opts.HostsFile)
		if cfg, err := loadSystem(opts.ResolvConf, opts.HostsFile); err == nil {
			if u, err := newUDPClient(cfg.servers, opts.PreferIPv6, r.net); err == nil {
				r.sys = &systemResolver{cfg: cfg, udp: u}
			}
		}
		if fb := parseServers(opts.Fallback); len(fb) > 0 {
			r.fbNet = newNetResolver(opts.Fallback)
			r.fb, _ = newUDPClient(fb, opts.PreferIPv6, r.fbNet)
		}
	}
	return r
}

// CheckSystem switches to the fallback servers if the system resolver does
// not answer at all within timeout. Any answer, NXDOMAIN included, counts
// as alive. The name is random so that a forwarder answering only from its
// cache (WSL's DNS proxy does) is not mistaken for a working one. It is a
// no-op without fallback servers.
func (r *CachingResolver) CheckSystem(timeout time.Duration) {
	if r.fb == nil || r.useFB.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var b [6]byte
	_, _ = rand.Read(b[:])
	_, err := r.systemLookup(ctx, "pulse-check-"+hex.EncodeToString(b[:])+".example.com")
	if isTimeout(err) {
		r.switchToFallback("the system resolver did not answer within " + timeout.String())
	}
}

// UsingFallback reports whether lookups go to the fallback servers.
func (r *CachingResolver) UsingFallback() bool { return r.useFB.Load() }

func (r *CachingResolver) switchToFallback(reason string) {
	if r.useFB.CompareAndSwap(false, true) && r.opts.OnFallback != nil {
		r.opts.OnFallback(reason)
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return de.IsTimeout
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// parseServers returns the servers as ip:port, or nil if any is not a literal
// address (then the Go resolver handles all of them).
func parseServers(servers []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
			continue
		}
		if ip, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
			out = append(out, netip.AddrPortFrom(ip.Unmap(), 53))
			continue
		}
		return nil
	}
	return out
}

func newNetResolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	addrs := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(strings.Trim(s, "[]"), "53")
		}
		addrs = append(addrs, s)
	}
	var next atomic.Uint64
	d := net.Dialer{Timeout: 3 * time.Second}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Round-robin across the configured servers; the Go resolver
			// retries on its own, so each retry may land on another server.
			server := addrs[next.Add(1)%uint64(len(addrs))]
			return d.DialContext(ctx, network, server)
		},
	}
}

// Lookups returns the number of lookups that missed the cache.
func (r *CachingResolver) Lookups() int64 { return r.lookups.Load() }

// Lookup returns the addresses for host, IPv4 first unless PreferIPv6 is set.
func (r *CachingResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if c, ok := r.cache.Get(host); ok && r.now().Before(c.expires) && !(c.sysTimeout && r.useFB.Load()) {
		return c.addrs, c.err
	}
	if r.opts.AutoCheck {
		r.checkOnce.Do(func() { go r.CheckSystem(systemTryTimeout) })
	}

	r.mu.Lock()
	c, ok := r.inflight[host]
	if !ok {
		c = &call{done: make(chan struct{})}
		r.inflight[host] = c
		go r.fill(host, c)
	}
	r.mu.Unlock()

	select {
	case <-c.done:
		return c.addrs, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// fill resolves host for every waiter of c and caches the answer.
func (r *CachingResolver) fill(host string, c *call) {
	var sys bool
	c.addrs, sys, c.err = r.resolve(host)
	ttl := r.opts.TTL
	if c.err != nil {
		ttl = r.opts.NegativeTTL
	}
	r.cache.Set(host, cached{addrs: c.addrs, err: c.err, expires: r.now().Add(ttl), sysTimeout: sys && isTimeout(c.err)})
	r.mu.Lock()
	delete(r.inflight, host)
	r.mu.Unlock()
	close(c.done)
}

// resolve performs the uncached lookup with its own deadline, detached from
// any caller, so one caller's cancellation never poisons the shared answer.
// sys reports whether the system resolver produced the answer.
func (r *CachingResolver) resolve(host string) (addrs []netip.Addr, sys bool, err error) {
	r.lookups.Add(1)
	addrs, sys, err = r.lookup(host)
	if sys && r.fb != nil {
		if isTimeout(err) {
			if r.timeouts.Add(1) >= fallbackAfter {
				r.switchToFallback("the system resolver timed out " + strconv.Itoa(fallbackAfter) + " times in a row")
			}
			// Ask the fallback for this name now, so no target is lost
			// while the system resolver is flaky.
			ctx, cancel := context.WithTimeout(context.Background(), r.opts.Timeout)
			addrs, err = r.fb.LookupNetIP(ctx, host)
			cancel()
			sys = false
		} else {
			r.timeouts.Store(0)
		}
	}
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) {
			err = &net.DNSError{Err: err.Error(), Name: host, IsTimeout: errors.Is(err, context.DeadlineExceeded)}
		}
		return nil, sys, err
	}
	if len(addrs) == 0 {
		return nil, sys, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	return order(addrs, r.opts.PreferIPv6), sys, nil
}

// lookup queries the active servers once; sys is true for the system
// resolver.
func (r *CachingResolver) lookup(host string) ([]netip.Addr, bool, error) {
	timeout := r.opts.Timeout
	if r.udp == nil && !r.useFB.Load() {
		timeout = r.systemTimeout()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	switch {
	case r.udp != nil:
		a, err := r.udp.LookupNetIP(ctx, host)
		return a, false, err
	case r.fb != nil && r.useFB.Load():
		if a := r.hosts[host]; len(a) > 0 {
			return a, false, nil // the hosts file still wins on the fallback
		}
		a, err := r.fb.LookupNetIP(ctx, host)
		return a, false, err
	default:
		a, err := r.systemLookup(ctx, host)
		return a, true, err
	}
}

func (r *CachingResolver) systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if r.sys != nil {
		return r.sys.lookup(ctx, host)
	}
	return r.net.LookupNetIP(ctx, "ip", host)
}

func order(addrs []netip.Addr, preferV6 bool) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	seen := make(map[netip.Addr]struct{}, len(addrs))
	for pass := 0; pass < 2; pass++ {
		wantV4 := (pass == 0) != preferV6
		for _, a := range addrs {
			a = a.Unmap()
			if a.Is4() != wantV4 {
				continue
			}
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	return out
}

// LookupTXT resolves TXT records through the servers address lookups use
// (uncached; callers cache what they need). Like address lookups, a name the
// system resolver does not answer is asked from the fallback servers.
func (r *CachingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	switch {
	case r.udp != nil:
		ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		return r.udp.LookupTXT(ctx, name)
	case r.fb != nil && r.useFB.Load():
		ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		return r.fb.LookupTXT(ctx, name)
	case r.sys != nil:
		sctx, cancel := context.WithTimeout(ctx, r.systemTimeout())
		recs, err := r.sys.udp.LookupTXT(sctx, name)
		cancel()
		if r.fb == nil || !isTimeout(err) || ctx.Err() != nil {
			return recs, err
		}
		ctx, cancel = context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		return r.fb.LookupTXT(ctx, name)
	}
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	return r.net.LookupTXT(ctx, name)
}

func defaultHostsFile() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// LookupCNAME returns the CNAME chain of host (empty if it has none),
// through the same servers address lookups use.
func (r *CachingResolver) LookupCNAME(ctx context.Context, host string) ([]string, error) {
	switch {
	case r.udp != nil:
		ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		return r.udp.LookupCNAME(ctx, host)
	case r.fb != nil && r.useFB.Load():
		ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		return r.fb.LookupCNAME(ctx, host)
	case r.sys != nil:
		sctx, cancel := context.WithTimeout(ctx, r.systemTimeout())
		chain, err := r.sys.udp.LookupCNAME(sctx, host)
		cancel()
		if r.fb == nil || !isTimeout(err) || len(chain) > 0 || ctx.Err() != nil {
			return chain, err
		}
		ctx, cancel = context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		return r.fb.LookupCNAME(ctx, host)
	}
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	c, err := r.net.LookupCNAME(ctx, host)
	if c = strings.TrimSuffix(strings.ToLower(c), "."); err != nil || c == "" || c == host {
		return nil, err
	}
	return []string{c}, nil
}

// systemTimeout bounds one system-resolver query: shorter when the fallback
// servers can still answer the name.
func (r *CachingResolver) systemTimeout() time.Duration {
	if r.fb != nil {
		return min(r.opts.Timeout, systemTryTimeout)
	}
	return r.opts.Timeout
}
