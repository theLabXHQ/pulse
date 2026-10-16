// Package probe performs single HTTP(S) probes: DNS (cached), connect, TLS,
// request, bounded body read, redirects and HTTPS/HTTP scheme detection.
// It knows nothing about scheduling, matching or output.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/theLabXHQ/pulse/internal/dns"
)

// Options configures a Client.
type Options struct {
	Timeout             time.Duration // per attempt, including redirects and body read
	Retries             int           // extra attempts after transient failures
	FollowRedirects     bool
	FollowHostRedirects bool // follow only redirects that stay on the same host
	MaxRedirects        int
	MaxBodySize         int64
	Method              string
	Body                string
	Raw                 []byte      // -unsafe: these bytes are sent as the request, unchanged
	Headers             http.Header // custom headers; "Host" sets the Host header
	UserAgent           string
	Proxy               string // http://, https:// or socks5:// URL; "" = environment
	HTTP2               bool   // offer h2 via ALPN
	Impersonate         bool   // retry blocked HTTPS pages with Chrome's TLS fingerprint (uTLS)
	RandomAgent         bool   // a random browser User-Agent per request (-random-agent)
	LeaveDefaultPorts   bool   // keep :80/:443 in request URLs and Host (-ldp)
	KeepAlive           bool   // reuse connections across probes of the same host
	MaxIdleConns        int
	SNI                 string
	Deny                []netip.Prefix // never connect to these addresses
	Resolver            dns.Resolver
	// BeforeAttempt is called before every scheme attempt and retry (not
	// before redirect hops); it is where rate limits are applied. An error
	// aborts the attempt as canceled.
	BeforeAttempt func(ctx context.Context) error
}

// Client is safe for concurrent use.
type Client struct {
	opts      Options
	transport *http.Transport
	rt        http.RoundTripper // the transport
	imp       http.RoundTripper // Chrome-fingerprint transport (-tls-impersonate), or nil
	dialer    net.Dialer
	proxyHost string
}

// DefaultUserAgent is a mainstream browser UA: identifying UAs are blocked
// by many WAFs, which turns live hosts into false 403s/drops. So are
// outdated browser versions ("Access denied, old Chrome version"), hence
// the version is derived from the current date, not frozen at build time.
var DefaultUserAgent = chromeUA("Windows NT 10.0; Win64; x64", currentMajor(time.Now(), chromeAnchor))

// New builds a Client.
func New(opts Options) (*Client, error) {
	if opts.Resolver == nil {
		return nil, errors.New("probe: resolver is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxBodySize <= 0 {
		opts.MaxBodySize = 1 << 20
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}
	if opts.Method == "" {
		opts.Method = http.MethodGet
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	if opts.MaxIdleConns <= 0 {
		opts.MaxIdleConns = 100
	}
	c := &Client{opts: opts, dialer: net.Dialer{KeepAlive: 15 * time.Second}}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // probing must see every server, valid cert or not
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allCipherSuites(),
		ServerName:         opts.SNI,
	}
	t := &http.Transport{
		DialContext:            c.dial,
		TLSClientConfig:        tlsCfg,
		DisableCompression:     true, // decoded in readBody, see there
		MaxIdleConns:           opts.MaxIdleConns,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        15 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 256 << 10,
		ForceAttemptHTTP2:      opts.HTTP2,
	}
	if !opts.HTTP2 {
		t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	if !opts.KeepAlive {
		// Not DisableKeepAlives: that sends "Connection: close", which no
		// browser does and some CDNs tarpit (azure.microsoft.com: +8 s).
		// A host gets one request, so a pooled connection is never
		// reused: a negative MaxIdleConnsPerHost closes it as soon as
		// the response is read. Pooling instead held ~2 fds per worker
		// and, closing evicted connections under the pool lock, cost
		// ~25% throughput. See rotatingTransport for the catch.
		t.MaxIdleConnsPerHost = -1
	}
	if opts.Proxy != "" {
		pu, err := url.Parse(opts.Proxy)
		if err != nil || pu.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL %q", opts.Proxy)
		}
		switch pu.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q", pu.Scheme)
		}
		t.Proxy = http.ProxyURL(pu)
		c.proxyHost = strings.ToLower(pu.Hostname())
	} else {
		t.Proxy = http.ProxyFromEnvironment
		if p, _ := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}); p != nil {
			c.proxyHost = strings.ToLower(p.Hostname())
		}
	}
	c.transport = t
	c.rt = t
	if !opts.KeepAlive {
		c.rt = newRotatingTransport(t, rotateEvery)
	}
	if opts.Impersonate {
		if c.proxyHost != "" {
			return nil, errImpersonateProxy
		}
		c.imp = newImpersonator(c, c.rt)
	}
	return c, nil
}

// Proxied reports whether requests go through a proxy.
func (c *Client) Proxied() bool { return c.proxyHost != "" }

// Resolve returns the addresses a probe of host would dial, from the shared
// cache. It is meaningless when Proxied.
func (c *Client) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	return c.opts.Resolver.Lookup(ctx, host)
}

// CNAME returns the CNAME chain of host when the resolver can tell.
func (c *Client) CNAME(ctx context.Context, host string) []string {
	if cr, ok := c.opts.Resolver.(interface {
		LookupCNAME(context.Context, string) ([]string, error)
	}); ok {
		chain, _ := cr.LookupCNAME(ctx, host)
		return chain
	}
	return nil
}

// browserAgents back -random-agent: current desktop browsers, so the
// Accept headers Pulse sends stay plausible for every one of them.
var browserAgents = func() []string {
	now := time.Now()
	ch, ff := currentMajor(now, chromeAnchor), currentMajor(now, firefoxAnchor)
	return []string{
		chromeUA("Windows NT 10.0; Win64; x64", ch),
		chromeUA("Macintosh; Intel Mac OS X 10_15_7", ch),
		chromeUA("X11; Linux x86_64", ch),
		chromeUA("Windows NT 10.0; Win64; x64", ch) + fmt.Sprintf(" Edg/%d.0.0.0", ch),
		firefoxUA("Windows NT 10.0; Win64; x64", ff),
		firefoxUA("X11; Linux x86_64", ff),
		firefoxUA("Macintosh; Intel Mac OS X 10.15", ff),
	}
}()

// releaseAnchor is a known stable major version and a date it was current.
// Chrome and Firefox both ship a major release every four weeks.
type releaseAnchor struct {
	major int
	date  time.Time
}

var (
	chromeAnchor  = releaseAnchor{156, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)}
	firefoxAnchor = releaseAnchor{158, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)}
)

// currentMajor estimates the stable major version at now. It never goes
// below the anchor, so a wrong clock cannot produce an ancient version.
func currentMajor(now time.Time, a releaseAnchor) int {
	if now.Before(a.date) {
		return a.major
	}
	return a.major + int(now.Sub(a.date)/(28*24*time.Hour))
}

func chromeUA(platform string, major int) string {
	// Chrome reports only the major version (UA reduction).
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", platform, major)
}

func firefoxUA(platform string, major int) string {
	return fmt.Sprintf("Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0", platform, major, major)
}

// Close releases idle connections.
func (c *Client) Close() {
	if ci, ok := c.rt.(interface{ CloseIdleConnections() }); ok {
		ci.CloseIdleConnections()
	}
}

func allCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	// Legacy suites are needed to talk to old appliances at all; this is a
	// prober, not a client protecting user data.
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

func (c *Client) denied(ip netip.Addr) bool {
	for _, p := range c.opts.Deny {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// dial resolves through the shared cache, enforces the network policy on the
// resolved address (so DNS cannot be used to reach denied ranges) and races
// up to maxDialAddrs addresses, Happy Eyeballs style (RFC 8305): the next
// address starts when the previous one has not connected within
// dialStagger or has failed. Trying them one after another instead lets a
// single dead address (common in multi-A records) take the whole timeout.
func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		tr := traceFrom(ctx)
		t0 := time.Now()
		ips, err = c.opts.Resolver.Lookup(ctx, host)
		if tr != nil && err == nil {
			tr.markDNS(t0, time.Now())
		}
		if err != nil {
			return nil, err
		}
	}
	isProxy := c.proxyHost != "" && strings.EqualFold(host, c.proxyHost)
	var targets []string
	var policyErr error
	for _, ip := range ips {
		if len(targets) == maxDialAddrs {
			break
		}
		if !isProxy && c.denied(ip) {
			policyErr = errPolicy{ip: ip.String()}
			continue
		}
		targets = append(targets, netip.AddrPortFrom(ip, uint16(port)).String())
	}
	switch len(targets) {
	case 0:
		return nil, policyErr
	case 1:
		return c.dialer.DialContext(ctx, network, targets[0])
	}
	return c.raceDial(ctx, network, targets)
}

const (
	maxDialAddrs = 4
	dialStagger  = 300 * time.Millisecond
)

// raceDial connects to the first of targets that answers. It returns the
// first address's error when all fail: that is the one a sequential dial
// would have reported.
func (c *Client) raceDial(ctx context.Context, network string, targets []string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		i    int
		conn net.Conn
		err  error
	}
	ch := make(chan result, len(targets))
	next, pending := 0, 0
	start := func() {
		i := next
		next++
		pending++
		go func() {
			conn, err := c.dialer.DialContext(ctx, network, targets[i])
			ch <- result{i, conn, err}
		}()
	}
	start()
	timer := time.NewTimer(dialStagger)
	defer timer.Stop()
	var firstErr error
	firstErrIdx := len(targets)
	for {
		select {
		case r := <-ch:
			pending--
			if r.err == nil {
				cancel()
				go func(n int) { // close connections that lost the race
					for ; n > 0; n-- {
						if r := <-ch; r.conn != nil {
							_ = r.conn.Close()
						}
					}
				}(pending)
				return r.conn, nil
			}
			if r.i < firstErrIdx {
				firstErr, firstErrIdx = r.err, r.i
			}
			if ctx.Err() == nil && next < len(targets) {
				start()
				timer.Reset(dialStagger)
			} else if pending == 0 {
				return nil, firstErr
			}
		case <-timer.C:
			if next < len(targets) {
				start()
				timer.Reset(dialStagger)
			}
		}
	}
}
