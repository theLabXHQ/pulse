package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/theLabXHQ/pulse/internal/target"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// staticResolver maps every name to 127.0.0.1 except names starting "nx".
type staticResolver struct{ lookups atomic.Int64 }

func (s *staticResolver) Lookup(_ context.Context, host string) ([]netip.Addr, error) {
	s.lookups.Add(1)
	if strings.HasPrefix(host, "nx") {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func newClient(t *testing.T, mod func(*Options)) *Client {
	t.Helper()
	o := Options{Timeout: 2 * time.Second, MaxBodySize: 1 << 20, Resolver: &staticResolver{}, Proxy: "", KeepAlive: false}
	if mod != nil {
		mod(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
	h, p, _ := net.SplitHostPort(u)
	port, _ := strconv.Atoi(p)
	return h, port
}

func TestProbePlainAndTitle(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("User-Agent") == "" || r.Header.Get("Accept-Encoding") != "gzip, deflate" {
			t.Errorf("missing default headers: %v", r.Header)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>ok</title>"))
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, nil)
	var buf bytes.Buffer
	r, f := c.Probe(context.Background(), Spec{Host: "app.test", Port: port, Path: "/x"}, &buf)
	if f != nil {
		t.Fatalf("unexpected failure: %v", f)
	}
	if r.StatusCode != 200 || r.Scheme != "http" || string(r.Body) != "<title>ok</title>" || r.IP != "127.0.0.1" {
		t.Fatalf("bad response: %+v", r)
	}
	if r.URL != "http://app.test:"+strconv.Itoa(port)+"/x" {
		t.Fatalf("url %q", r.URL)
	}
	if hits.Load() != 1 || len(r.Attempts) != 1 {
		t.Fatalf("expected exactly one request, got %d hits %d attempts", hits.Load(), len(r.Attempts))
	}
}

func TestGzipVariantsNeedNoSecondRequest(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("<title>zipped</title>"))
	_ = zw.Close()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Encoding", "gzip")
		if r.URL.Path == "/bad" {
			_, _ = w.Write([]byte("<title>plain</title>")) // mislabeled
			return
		}
		_, _ = w.Write(gz.Bytes())
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, nil)
	var buf bytes.Buffer
	r, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/good"}, &buf)
	if f != nil || string(r.Body) != "<title>zipped</title>" || r.Encoding != "gzip" {
		t.Fatalf("gzip: %v %+v", f, r)
	}
	r, f = c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/bad"}, &buf)
	if f != nil || string(r.Body) != "<title>plain</title>" {
		t.Fatalf("mislabeled gzip: %v %+v", f, r)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected 2 requests total, got %d", hits.Load())
	}
}

func TestBodyLimitAndDecompressionBomb(t *testing.T) {
	var bomb bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&bomb, gzip.BestCompression)
	_, _ = zw.Write(make([]byte, 64<<20))
	_ = zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(bomb.Bytes())
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, func(o *Options) { o.MaxBodySize = 4096 })
	var buf bytes.Buffer
	r, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http"}, &buf)
	if f != nil {
		t.Fatal(f)
	}
	if len(r.Body) != 4096 || !r.BodyTruncated {
		t.Fatalf("body %d truncated=%v", len(r.Body), r.BodyTruncated)
	}
}

func TestSlowBodyIsAliveWithWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<title>slow</title>"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, func(o *Options) { o.Timeout = 300 * time.Millisecond })
	var buf bytes.Buffer
	r, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http"}, &buf)
	if f != nil {
		t.Fatalf("server answered; must be alive, got %v", f)
	}
	if string(r.Body) != "<title>slow</title>" || len(r.Warnings) == 0 || r.Warnings[0] != "body_timeout" {
		t.Fatalf("got body %q warnings %v", r.Body, r.Warnings)
	}
}

func TestHeaderTimeoutClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, func(o *Options) { o.Timeout = 200 * time.Millisecond })
	var buf bytes.Buffer
	_, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http"}, &buf)
	if f == nil || f.Class != ClassResponseTimout || f.Phase != PhaseResponse {
		t.Fatalf("want response_timeout, got %+v", f)
	}
}

func TestRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/end", http.StatusMovedPermanently)
		case "/loop1":
			http.Redirect(w, r, "/loop2", http.StatusFound)
		case "/loop2":
			http.Redirect(w, r, "/loop1", http.StatusFound)
		case "/away":
			http.Redirect(w, r, "http://elsewhere.test/", http.StatusFound)
		default:
			_, _ = w.Write([]byte("end"))
		}
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	var buf bytes.Buffer

	plain := newClient(t, nil)
	r, _ := plain.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/start"}, &buf)
	if r.StatusCode != 301 || r.FinalURL != "" || len(r.Chain) != 0 {
		t.Fatalf("not following: %+v", r)
	}

	follow := newClient(t, func(o *Options) { o.FollowRedirects = true })
	r, _ = follow.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/start"}, &buf)
	if r.StatusCode != 200 || !strings.HasSuffix(r.FinalURL, "/end") || len(r.Chain) != 2 || r.Chain[0].StatusCode != 301 {
		t.Fatalf("follow: %+v", r)
	}
	r, f := follow.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/loop1"}, &buf)
	if f != nil || r.StatusCode != 302 || len(r.Warnings) != 1 || r.Warnings[0] != string(ClassRedirectLoop) {
		t.Fatalf("loop: %v %+v", f, r)
	}

	sameHost := newClient(t, func(o *Options) { o.FollowHostRedirects = true })
	r, _ = sameHost.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/away"}, &buf)
	if r.StatusCode != 302 {
		t.Fatalf("cross-host redirect must not be followed with -fhr: %+v", r)
	}
}

func TestTLSOnExplicitPortViaPlaintext400(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>secure</title>"))
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, nil)
	var buf bytes.Buffer
	// Port > 1024 => HTTP first; Go's TLS server answers plaintext with 400.
	r, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port}, &buf)
	if f != nil {
		t.Fatal(f)
	}
	if r.Scheme != "https" || r.StatusCode != 200 || string(r.Body) != "<title>secure</title>" || r.TLS == nil {
		t.Fatalf("expected https upgrade, got %+v", r)
	}
	if len(r.Attempts) != 2 || r.Attempts[0].Status != 400 {
		t.Fatalf("attempt evidence missing: %+v", r.Attempts)
	}
}

func TestPlainServerProbedAsHTTPSFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hi")) }))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, nil)
	var buf bytes.Buffer
	_, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "https"}, &buf)
	if f == nil || f.Class != ClassPlainOnTLS {
		t.Fatalf("want %s, got %+v", ClassPlainOnTLS, f)
	}
}

func TestConnectionLevelFailuresDoNotFallBack(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nothing listens now
	res := &staticResolver{}
	c := newClient(t, func(o *Options) { o.Resolver = res })
	var buf bytes.Buffer
	_, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port}, &buf)
	if f == nil || f.Class != ClassConnRefused || len(f.Attempts) != 1 {
		t.Fatalf("refused on explicit port must not retry the other scheme: %+v", f)
	}
	_, f = c.Probe(context.Background(), Spec{Host: "nx.test"}, &buf)
	if f == nil || f.Class != ClassDNSNotFound || len(f.Attempts) != 1 {
		t.Fatalf("NXDOMAIN must not retry the other scheme: %+v", f)
	}
}

func TestPlaintextHangDoesNotRetryTLS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	var conns atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	c := newClient(t, func(o *Options) { o.Timeout = 150 * time.Millisecond })
	var buf bytes.Buffer
	start := time.Now()
	_, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: ln.Addr().(*net.TCPAddr).Port}, &buf)
	if f == nil || f.Class != ClassResponseTimout || len(f.Attempts) != 1 || conns.Load() != 1 {
		t.Fatalf("want one response_timeout attempt, got %+v conns=%d", f, conns.Load())
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Fatal("must not spend a second timeout on TLS")
	}
}

func TestResetClassified(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()
		}
	}()
	c := newClient(t, nil)
	var buf bytes.Buffer
	_, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: ln.Addr().(*net.TCPAddr).Port, Scheme: "http"}, &buf)
	if f == nil || (f.Class != ClassConnReset && f.Class != ClassConnClosed) {
		t.Fatalf("want conn_reset/conn_closed, got %+v", f)
	}
}

func TestDenyPolicyAppliesAfterDNS(t *testing.T) {
	c := newClient(t, func(o *Options) { o.Deny = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
	var buf bytes.Buffer
	_, f := c.Probe(context.Background(), Spec{Host: "rebind.test", Port: 80, Scheme: "http"}, &buf)
	if f == nil || f.Class != ClassPolicy {
		t.Fatalf("want policy_denied, got %+v", f)
	}
}

func TestRetriesOnlyTransientErrors(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	var attempts atomic.Int64
	c := newClient(t, func(o *Options) {
		o.Retries = 2
		o.BeforeAttempt = func(context.Context) error { attempts.Add(1); return nil }
	})
	var buf bytes.Buffer
	r, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http"}, &buf)
	if f != nil || r.StatusCode != 204 || attempts.Load() != 2 {
		t.Fatalf("retry: %v %+v attempts=%d", f, r, attempts.Load())
	}
}

func TestSchemeOrderUsedForDefaultPorts(t *testing.T) {
	if target.SchemeOrder(0)[0] != target.SchemeHTTPS {
		t.Fatal("default ports must try https first")
	}
}

func TestBrotliAndZstd(t *testing.T) {
	page := "<html><title>compressed</title>" + strings.Repeat("<p>lorem ipsum</p>", 500) + "</html>"
	enc := map[string]func([]byte) []byte{
		"br": func(b []byte) []byte {
			var out bytes.Buffer
			w := brotli.NewWriter(&out)
			_, _ = w.Write(b)
			_ = w.Close()
			return out.Bytes()
		},
		"zstd": func(b []byte) []byte {
			w, _ := zstd.NewWriter(nil)
			defer w.Close()
			return w.EncodeAll(b, nil)
		},
	}
	bomb := make([]byte, 64<<20)
	for name, compress := range enc {
		good, bombed := compress([]byte(page)), compress(bomb)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", name)
			switch r.URL.Path {
			case "/bad":
				_, _ = w.Write([]byte("<!DOCTYPE html><title>plain</title>")) // mislabeled
			case "/bomb":
				_, _ = w.Write(bombed)
			default:
				_, _ = w.Write(good)
			}
		}))
		_, port := hostPort(t, srv.URL)
		c := newClient(t, func(o *Options) { o.MaxBodySize = 64 << 10 })
		var buf bytes.Buffer
		r, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/"}, &buf)
		if f != nil || string(r.Body) != page || r.Encoding != name || len(r.Warnings) != 0 {
			t.Fatalf("%s: %v enc=%q warnings=%v body=%.40q", name, f, r.Encoding, r.Warnings, r.Body)
		}
		r, f = c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/bad"}, &buf)
		if f != nil || string(r.Body) != "<!DOCTYPE html><title>plain</title>" || r.Encoding != "" {
			t.Fatalf("%s mislabeled: %v %+v", name, f, r)
		}
		r, f = c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http", Path: "/bomb"}, &buf)
		if f != nil {
			t.Fatalf("%s bomb: %v", name, f)
		}
		if len(r.Body) != 64<<10 || !r.BodyTruncated {
			t.Fatalf("%s bomb: len=%d truncated=%v", name, len(r.Body), r.BodyTruncated)
		}
		srv.Close()
	}
}

// Browsers never send "Connection: close"; some CDNs delay requests that do.
func TestNoConnectionCloseHeader(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(fmt.Sprintf("close=%v connection=%q", r.Close, r.Header.Get("Connection")))
	}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, func(o *Options) { o.KeepAlive = false })
	var buf bytes.Buffer
	if _, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http"}, &buf); f != nil {
		t.Fatal(f)
	}
	if s := got.Load(); s != `close=false connection=""` {
		t.Fatalf("request had %v", s)
	}
}

// Without keep-alive the connection is closed soon after the response,
// not left in the idle pool for long (one request per host: never reused).
func TestNoKeepAliveClosesConnection(t *testing.T) {
	closed := make(chan struct{}, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			closed <- struct{}{}
		}
	}
	srv.Start()
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, func(o *Options) { o.KeepAlive = false })
	var buf bytes.Buffer
	if _, f := c.Probe(context.Background(), Spec{Host: "a.test", Port: port, Scheme: "http"}, &buf); f != nil {
		t.Fatal(f)
	}
	select {
	case <-closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("connection still open after the response was read")
	}
}

// HTTP/2 must work without keep-alive too: net/http keeps h2 connections
// in the idle pool, and a pool that refuses them would close the
// connection under the request.
func TestHTTP2WithoutKeepAlive(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<title>"+r.Proto+"</title>")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, func(o *Options) { o.KeepAlive = false; o.HTTP2 = true })
	for i := 0; i < 3; i++ {
		var buf bytes.Buffer
		r, f := c.Probe(context.Background(), Spec{Host: fmt.Sprintf("h%d.test", i), Port: port, Scheme: "https"}, &buf)
		if f != nil {
			t.Fatal(f)
		}
		if r.StatusCode != 200 || !strings.Contains(string(r.Body), "HTTP/2.0") {
			t.Fatalf("got %d %q", r.StatusCode, r.Body)
		}
	}
}

// Without keep-alive, memory must not grow with the number of distinct
// hosts probed (net/http's per-host wait lists; see rotatingTransport).
func TestNoKeepAliveMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("probes thousands of hosts")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	c := newClient(t, func(o *Options) { o.KeepAlive = false })
	var buf bytes.Buffer
	probe := func(from, to int) {
		for i := from; i < to; i++ {
			if _, f := c.Probe(context.Background(), Spec{Host: fmt.Sprintf("h%d.test", i), Port: port, Scheme: "http"}, &buf); f != nil {
				t.Fatal(f)
			}
		}
	}
	heap := func() uint64 {
		var m runtime.MemStats
		runtime.GC() // two cycles: sync.Pool keeps objects for one
		runtime.GC()
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	probe(0, 2*rotateEvery) // warm up: pools, caches
	// A real leak grows the heap on every attempt; other tests running in
	// parallel (and -race bookkeeping) only add noise to some of them.
	const n = 4 * rotateEvery
	next := 2 * rotateEvery
	var grew int64
	for attempt := 0; attempt < 3; attempt++ {
		before := heap()
		probe(next, next+n)
		next += n
		if grew = int64(heap()) - int64(before); grew <= n*100 {
			return
		}
		t.Logf("attempt %d: heap grew %d B over %d hosts", attempt+1, grew, n)
	}
	t.Fatalf("heap grew %d B over %d hosts (%d B/host)", grew, n, grew/n)
}

// Every way Pulse opens a connection must go through the policy-enforcing
// dialer, including the -pipeline and -http2 probes.
func TestDenyPolicyCoversAllPaths(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	deny := func(o *Options) { o.Deny = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} }
	ctx := context.Background()
	var buf bytes.Buffer
	wantDenied := func(name string, f *Failure) {
		t.Helper()
		if f == nil || f.Class != ClassPolicy {
			t.Errorf("%s: want policy_denied, got %+v", name, f)
		}
	}

	c := newClient(t, func(o *Options) { deny(o); o.HTTP2 = true; o.Impersonate = true })
	for _, scheme := range []string{"http", "https"} {
		_, f := c.Probe(ctx, Spec{Host: "rebind.test", Port: port, Scheme: scheme}, &buf)
		wantDenied("probe "+scheme, f)
	}
	_, f := c.Fetch(ctx, fmt.Sprintf("http://rebind.test:%d/favicon.ico", port), &buf)
	wantDenied("fetch", f)
	_, f = c.lenientFetch(ctx, Spec{Host: "rebind.test"}, "http", port, fmt.Sprintf("http://rebind.test:%d/", port), &buf)
	wantDenied("lenient", f)
	if c.Pipeline(ctx, "http", "rebind.test", port) {
		t.Error("pipeline: reported support through a denied address")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://rebind.test:%d/", port), nil)
	if resp, err := c.imp.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Error("impersonate: request went through")
	}

	raw := newClient(t, func(o *Options) { deny(o); o.Raw = []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n") })
	_, f = raw.Probe(ctx, Spec{Host: "rebind.test", Port: port, Scheme: "http"}, &buf)
	wantDenied("raw", f)

	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connection(s) reached a denied address", n)
	}
}

type addrsResolver []netip.Addr

func (a addrsResolver) Lookup(context.Context, string) ([]netip.Addr, error) { return a, nil }

// blackhole makes connects to 127.0.0.2 hang until the dial is abandoned,
// like a firewalled address that drops SYNs.
func blackhole(c *Client) {
	c.dialer.ControlContext = func(ctx context.Context, _, address string, _ syscall.RawConn) error {
		if strings.HasPrefix(address, "127.0.0.2:") {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
}

// A dead address first in a multi-address record must not use up the
// timeout: the next address is tried after dialStagger.
func TestDialRacesPastDeadAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port := hostPort(t, srv.URL)
	dead, live := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")
	c := newClient(t, func(o *Options) {
		o.Timeout = 5 * time.Second
		o.Resolver = addrsResolver{dead, dead, dead, live}
	})
	blackhole(c)
	var buf bytes.Buffer
	t0 := time.Now()
	r, f := c.Probe(context.Background(), Spec{Host: "multi.test", Port: port, Scheme: "http"}, &buf)
	if f != nil {
		t.Fatal(f)
	}
	if took := time.Since(t0); took > 2*time.Second || r.IP != "127.0.0.1" {
		t.Fatalf("connected to %s after %v", r.IP, took)
	}
}

func TestDialAllAddressesDead(t *testing.T) {
	dead := netip.MustParseAddr("127.0.0.2")
	c := newClient(t, func(o *Options) {
		o.Timeout = time.Second
		o.Resolver = addrsResolver{dead, dead}
	})
	blackhole(c)
	var buf bytes.Buffer
	t0 := time.Now()
	_, f := c.Probe(context.Background(), Spec{Host: "multi.test", Port: 80, Scheme: "http"}, &buf)
	if f == nil || f.Class != ClassConnTimeout {
		t.Fatalf("want conn_timeout, got %+v", f)
	}
	if took := time.Since(t0); took > 3*time.Second {
		t.Fatalf("took %v", took)
	}
}

func TestBrowserVersionFollowsDate(t *testing.T) {
	a := releaseAnchor{156, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)}
	for _, c := range []struct {
		at   time.Time
		want int
	}{
		{a.date, 156},
		{a.date.AddDate(0, 0, 27), 156},
		{a.date.AddDate(0, 0, 28), 157},
		{a.date.AddDate(1, 0, 0), 169},
		{a.date.AddDate(-1, 0, 0), 156}, // clock behind: never older than the anchor
	} {
		if got := currentMajor(c.at, a); got != c.want {
			t.Errorf("%v: got %d, want %d", c.at, got, c.want)
		}
	}
	if !strings.Contains(DefaultUserAgent, fmt.Sprintf("Chrome/%d.0.0.0 ", currentMajor(time.Now(), chromeAnchor))) {
		t.Errorf("DefaultUserAgent = %q", DefaultUserAgent)
	}
}
