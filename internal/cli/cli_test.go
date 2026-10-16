package cli

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/theLabXHQ/pulse/internal/cdn"
	"github.com/theLabXHQ/pulse/internal/engine"
	"github.com/theLabXHQ/pulse/internal/output"
	"golang.org/x/net/dns/dnsmessage"
)

type syncBuf struct {
	mu    sync.Mutex
	b     bytes.Buffer
	delay time.Duration
}

func (s *syncBuf) Write(p []byte) (int, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func run(t *testing.T, args []string, stdout *syncBuf, sigs chan os.Signal) (int, string) {
	t.Helper()
	var stderr syncBuf
	code := Main(args, Env{Stdin: strings.NewReader(""), Stdout: stdout, Stderr: &stderr, Signals: sigs})
	return code, stderr.String()
}

func results(t *testing.T, out string) []output.Result {
	t.Helper()
	var rs []output.Result
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		var r output.Result
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad JSONL line %q: %v", sc.Text(), err)
		}
		rs = append(rs, r)
	}
	return rs
}

func TestJSONOutputMatchersAndDedupe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<title>page %s</title>", r.URL.Path)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	list := filepath.Join(t.TempDir(), "in.txt")
	content := strings.Join([]string{host + "/a", host + "/a", host + "/missing", "   ", "bad target!", host + "/b"}, "\n")
	if err := os.WriteFile(list, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	code, stderr := run(t, []string{"-l", list, "-j", "-fc", "404", "-rl", "0"}, &out, nil)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	rs := results(t, out.String())
	if len(rs) != 2 {
		t.Fatalf("want 2 results (dedupe + -fc 404), got %d:\n%s", len(rs), out.String())
	}
	for _, r := range rs {
		if r.Schema != "pulse.v1" || r.StatusCode != 200 || !strings.HasPrefix(r.Title, "page /") || r.Scheme != "http" {
			t.Fatalf("bad result %+v", r)
		}
	}
	if !strings.Contains(stderr, "1 filtered") || !strings.Contains(stderr, "1 invalid inputs") || !strings.Contains(stderr, "1 duplicates") {
		t.Fatalf("summary missing counts: %s", stderr)
	}
}

func TestPerHostConcurrencyLimit(t *testing.T) {
	var cur, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		cur.Add(-1)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var paths []string
	for i := 0; i < 20; i++ {
		paths = append(paths, fmt.Sprintf("/p%d", i))
	}
	var out syncBuf
	code, stderr := run(t, []string{"-u", host, "-path", strings.Join(paths, ","), "-ch", "2", "-t", "10", "-rl", "0", "-j"}, &out, nil)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if n := len(results(t, out.String())); n != 20 {
		t.Fatalf("want 20 results, got %d", n)
	}
	if p := peak.Load(); p > 2 {
		t.Fatalf("per-host concurrency exceeded: peak %d", p)
	}
}

func TestSlowConsumerLosesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var targets []string
	for i := 0; i < 300; i++ {
		targets = append(targets, fmt.Sprintf("%s/t%d", host, i))
	}
	out := &syncBuf{delay: 2 * time.Millisecond}
	code, stderr := run(t, []string{"-u", strings.Join(targets, ","), "-t", "20", "-ch", "0", "-rl", "0", "-silent"}, out, nil)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if n := strings.Count(out.String(), "\n"); n != 300 {
		t.Fatalf("want 300 lines, got %d", n)
	}
}

func TestInterruptAndResume(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()
	list := filepath.Join(dir, "in.txt")
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, fmt.Sprintf("%s/r%d", host, i))
	}
	if err := os.WriteFile(list, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	resume := filepath.Join(dir, "resume.json")
	args := []string{"-l", list, "-t", "2", "-rl", "0", "-j", "-resume", resume}

	sigs := make(chan os.Signal, 1)
	var out1 syncBuf
	go func() {
		// Interrupt once some results exist (a fixed delay is flaky under -race).
		for strings.Count(out1.String(), "\n") < 3 {
			time.Sleep(10 * time.Millisecond)
		}
		sigs <- os.Interrupt
	}()
	code, stderr := run(t, args, &out1, sigs)
	if code != ExitInterrupted {
		t.Fatalf("want exit %d, got %d: %s", ExitInterrupted, code, stderr)
	}
	cp, err := engine.LoadCheckpoint(resume)
	if err != nil || cp.NextLine == 0 || cp.NextLine >= 40 {
		t.Fatalf("checkpoint %+v %v", cp, err)
	}
	first := results(t, out1.String())
	if int64(len(first)) < cp.NextLine {
		t.Fatalf("watermark %d ahead of %d written results", cp.NextLine, len(first))
	}

	var out2 syncBuf
	code, stderr = run(t, args, &out2, nil)
	if code != ExitOK {
		t.Fatalf("resume run exit %d: %s", code, stderr)
	}
	seen := map[string]bool{}
	for _, r := range append(first, results(t, out2.String())...) {
		seen[r.Input] = true
	}
	if len(seen) != 40 {
		t.Fatalf("resume lost targets: have %d of 40", len(seen))
	}
	if _, err := os.Stat(resume); !os.IsNotExist(err) {
		t.Fatal("resume file must be removed after a complete run")
	}
}

func TestUsageErrors(t *testing.T) {
	var out syncBuf
	if code, _ := run(t, []string{}, &out, nil); code != ExitUsage {
		t.Fatalf("no input must be a usage error, got %d", code)
	}
	if code, _ := run(t, []string{"-u", "x", "-p", "99999"}, &out, nil); code != ExitUsage {
		t.Fatal("bad ports must be a usage error")
	}
	if code, _ := run(t, []string{"-u", "x", "-json", "-csv"}, &out, nil); code != ExitUsage {
		t.Fatal("-json with -csv must be rejected")
	}
	if code, _ := run(t, []string{"-version"}, &out, nil); code != ExitOK || !strings.Contains(out.String(), "pulse") {
		t.Fatal("version")
	}
}

func TestCDNFieldsAndFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<title>x</title>")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	db, err := cdn.New(map[string]map[string][]string{"waf": {"cloudflare": {"127.0.0.0/8"}}})
	if err != nil {
		t.Fatal(err)
	}
	runCDN := func(args ...string) (int, string, string) {
		var out, errb syncBuf
		code := Main(append([]string{"-u", host, "-silent", "-nc"}, args...),
			Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, CDN: db})
		return code, out.String(), errb.String()
	}

	_, out, _ := runCDN("-j")
	rs := results(t, out)
	if len(rs) != 1 || !rs[0].CDN || rs[0].CDNName != "cloudflare" || rs[0].CDNType != "waf" {
		t.Fatalf("JSON must carry cdn fields: %+v", rs)
	}
	if _, out, _ := runCDN("-cdn"); !strings.Contains(out, "[cloudflare]") {
		t.Fatalf("text -cdn: %q", out)
	}
	cloudDB, _ := cdn.New(map[string]map[string][]string{"cloud": {"aws": {"127.0.0.0/8"}}})
	var cout, cerr syncBuf
	Main([]string{"-u", host, "-silent", "-nc", "-j"}, Env{Stdin: strings.NewReader(""), Stdout: &cout, Stderr: &cerr, CDN: cloudDB})
	if rs := results(t, cout.String()); len(rs) != 1 || rs[0].CDN || rs[0].CDNName != "aws" || rs[0].CDNType != "cloud" {
		t.Fatalf("cloud range: want cdn=false with name/type, got %+v", rs)
	}
	if _, out, _ := runCDN("-sc"); strings.Contains(out, "cloudflare") {
		t.Fatalf("text without -cdn must not show the provider: %q", out)
	}
	for args, kept := range map[string]bool{
		"-mcdn cloudflare": true, "-mcdn waf": true, "-mcdn fastly": false,
		"-fcdn WAF": false, "-fcdn cloudflare,": false, "-fcdn fastly": true,
	} {
		code, out, stderr := runCDN(strings.Fields(args)...)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", args, code, stderr)
		}
		if got := strings.TrimSpace(out) != ""; got != kept {
			t.Errorf("%s: kept=%v, want %v (out %q)", args, got, kept, out)
		}
	}
	if code, _, stderr := runCDN("-mcdn", "nosuchcdn"); code == 0 || !strings.Contains(stderr, "unknown provider") {
		t.Fatalf("unknown provider must be rejected: %d %q", code, stderr)
	}
}

func TestExcludeCDNSkipsOnlyCDNAndWAFPorts(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, "<title>x</title>")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://") // 127.0.0.1:<random port>
	for kind, skipped := range map[string]bool{"waf": true, "cdn": true, "cloud": false} {
		db, err := cdn.New(map[string]map[string][]string{kind: {"cloudflare": {"127.0.0.0/8"}}})
		if err != nil {
			t.Fatal(err)
		}
		hits.Store(0)
		var out, errb syncBuf
		code := Main([]string{"-u", host, "-ec", "-j", "-probe", "-silent", "-nc"},
			Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, CDN: db})
		rs := results(t, out.String())
		if code != 0 || len(rs) != 1 {
			t.Fatalf("%s: exit %d, %d results: %s", kind, code, len(rs), errb.String())
		}
		if skipped {
			if rs[0].Error == nil || rs[0].Error.Class != "cdn_port_skipped" || hits.Load() != 0 {
				t.Errorf("%s: want skipped without a request, got %+v (hits %d)", kind, rs[0].Error, hits.Load())
			}
		} else if rs[0].Failed || hits.Load() == 0 {
			t.Errorf("%s: cloud addresses must still be probed: %+v", kind, rs[0])
		}
	}
}

// pulseTestDNS answers every A query with 127.0.0.1.
func pulseTestDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			// Every name resolves, so an out-of-scope probe would reach the
			// server and show up.
			ok := true
			rh := dnsmessage.Header{ID: h.ID, Response: true}
			if !ok {
				rh.RCode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, rh)
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if ok && q.Type == dnsmessage.TypeA {
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
			}
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func selfSignedCert(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSAndCSPDiscoveryStaysInScope(t *testing.T) {
	var mu sync.Mutex
	hostsSeen := map[string]int{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hostsSeen[strings.Split(r.Host, ":")[0]]++
		mu.Unlock()
		w.Header().Set("Content-Security-Policy", "script-src 'self' https://cdn.pulse.test other.example.org")
		_, _ = fmt.Fprint(w, "<title>x</title>")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{
		selfSignedCert(t, "www.pulse.test", "api.pulse.test", "*.pulse.test", "other.example")}}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	dnsAddr := pulseTestDNS(t)

	run := func(extra ...string) map[string]output.Result {
		var out, errb syncBuf
		args := append([]string{"-u", "www.pulse.test", "-p", "https:" + port, "-r", dnsAddr, "-j", "-silent", "-nc", "-timeout", "5s"}, extra...)
		if code := Main(args, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		got := map[string]output.Result{}
		for _, r := range results(t, out.String()) {
			got[r.Host] = r
		}
		return got
	}

	got := run("-tls-probe", "-csp-probe")
	want := map[string]string{
		"www.pulse.test": "",
		"api.pulse.test": "tls:www.pulse.test",
		"pulse.test":     "tls:www.pulse.test", // from *.pulse.test
		"cdn.pulse.test": "csp:www.pulse.test",
	}
	if len(got) != len(want) {
		t.Fatalf("got hosts %v, want %v", keys(got), want)
	}
	for h, via := range want {
		if r, ok := got[h]; !ok || r.DiscoveredFrom != via || r.StatusCode != 200 {
			t.Errorf("%s: %+v, want discovered_from %q", h, r, via)
		}
	}
	mu.Lock()
	if hostsSeen["other.example"]+hostsSeen["other.example.org"] != 0 {
		t.Errorf("out-of-scope names were probed: %v", hostsSeen)
	}
	mu.Unlock()

	if got := run(); len(got) != 1 {
		t.Fatalf("without -tls-probe/-csp-probe only the input is probed, got %v", keys(got))
	}
	if got := run("-tls-probe", "-discover-max", "1"); len(got) != 2 {
		t.Fatalf("-discover-max 1 must cap discovery, got %v", keys(got))
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDiscoveryDepth(t *testing.T) {
	// A chain: www names l1 in its CSP, l1 names l2, l2 names l3.
	next := map[string]string{"www.pulse.test": "l1.pulse.test", "l1.pulse.test": "l2.pulse.test", "l2.pulse.test": "l3.pulse.test"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := next[strings.Split(r.Host, ":")[0]]; n != "" {
			w.Header().Set("Content-Security-Policy", "img-src "+n)
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	dnsAddr := pulseTestDNS(t)
	for depth, want := range map[string]int{"1": 2, "2": 3, "3": 4} {
		var out, errb syncBuf
		code := Main([]string{"-u", "www.pulse.test", "-p", "http:" + port, "-r", dnsAddr, "-j", "-silent", "-nc",
			"-csp-probe", "-discover-depth", depth}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
		if rs := results(t, out.String()); code != 0 || len(rs) != want {
			t.Errorf("-discover-depth %s: %d results, want %d (exit %d %s)", depth, len(rs), want, code, errb.String())
		}
	}
}

func TestASNFromFileDB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<title>x</title>")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	db := filepath.Join(t.TempDir(), "ip2asn.tsv")
	if err := os.WriteFile(db, []byte("127.0.0.0\t127.255.255.255\t64500\tZZ\tPULSE-TEST\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runASN := func(args ...string) (int, string, string) {
		var out, errb syncBuf
		code := Main(append([]string{"-u", host, "-silent", "-nc"}, args...),
			Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
		return code, out.String(), errb.String()
	}
	_, out, _ := runASN("-j", "-asn-db", db)
	rs := results(t, out)
	if len(rs) != 1 || rs[0].ASN == nil || rs[0].ASN.AsNumber != "AS64500" || rs[0].ASN.AsName != "PULSE-TEST" ||
		rs[0].ASN.AsCountry != "ZZ" || strings.Join(rs[0].ASN.AsRange, ",") != "127.0.0.0/8" {
		t.Fatalf("asn: %+v", rs)
	}
	if _, out, _ := runASN("-asn-db", db); !strings.Contains(out, "[AS64500, PULSE-TEST, ZZ]") {
		t.Fatalf("text output: %q", out)
	}
	if _, out, _ := runASN("-j"); strings.Contains(out, `"asn"`) {
		t.Fatalf("no ASN lookup without -asn: %q", out)
	}
	if code, _, stderr := runASN("-asn-db", filepath.Join(t.TempDir(), "missing.tsv")); code != ExitUsage || !strings.Contains(stderr, "-asn-db") {
		t.Fatalf("missing db: exit %d %q", code, stderr)
	}
}

func TestAdaptiveBacksOffThrottlingHost(t *testing.T) {
	// A WAF-like host: answers 429 (Retry-After: 1) to requests that come
	// less than 150ms after the previous one (measured on arrival, so it
	// sits below the 200ms gap two 429s produce, leaving connection-setup
	// jitter some room).
	var mu sync.Mutex
	var last time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tooSoon := time.Since(last) < 150*time.Millisecond
		last = time.Now()
		mu.Unlock()
		if tooSoon {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	throttled := func(extra ...string) int {
		mu.Lock()
		last = time.Time{}
		mu.Unlock()
		var out, errb syncBuf
		args := append([]string{"-u", host, "-path", "/a,/b,/c,/d,/e,/f", "-ch", "4", "-j", "-silent", "-nc"}, extra...)
		if code := Main(args, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		n := 0
		for _, r := range results(t, out.String()) {
			if r.StatusCode == 429 {
				n++
			}
		}
		return n
	}
	plain, adaptive := throttled(), throttled("-adaptive")
	// Slow start lets two requests overlap before the first 429 arrives, so
	// a few 429s are inherent; the point is far fewer than without.
	if plain < 4 || adaptive > 3 || adaptive >= plain {
		t.Fatalf("429 responses: %d without -adaptive, %d with; want many vs at most 3", plain, adaptive)
	}
}

func TestBannerOnlyOnTerminalStderr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	for _, c := range []struct {
		tty    bool
		args   []string
		banner bool
	}{
		{true, nil, true},
		{true, []string{"-silent"}, false},
		{false, nil, false},
	} {
		var out, errb syncBuf
		Main(append([]string{"-u", host, "-nc"}, c.args...),
			Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StderrTTY: c.tty})
		if got := strings.Contains(errb.String(), "/_/"); got != c.banner {
			t.Errorf("tty=%v %v: banner=%v, want %v", c.tty, c.args, got, c.banner)
		}
		if strings.Contains(out.String(), "/_/") {
			t.Errorf("banner must never reach stdout")
		}
	}
}

func TestDSLMatchersAndFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.Header().Set("X-Powered-By", "PHP/8.2")
			_, _ = fmt.Fprint(w, `<html><head><title>Admin Login</title><meta name="generator" content="WordPress 6.4"></head><body>wp-content</body></html>`)
		case "/missing":
			w.WriteHeader(404)
			_, _ = fmt.Fprint(w, "<title>Not Found</title>")
		default:
			_, _ = fmt.Fprint(w, "<title>Home</title>hello")
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	paths := func(args ...string) (string, int, string) {
		var out, errb syncBuf
		code := Main(append([]string{"-u", host, "-path", "/,/admin,/missing", "-j", "-silent", "-nc"}, args...),
			Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
		var got []string
		for _, r := range results(t, out.String()) {
			got = append(got, r.Path)
		}
		sort.Strings(got)
		return strings.Join(got, ","), code, errb.String()
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-mdc", `status_code == 200 && contains(to_lower(title), "admin")`}, "/admin"},
		{[]string{"-mdc", `status_code == 404`, "-mdc", `contains(body, "hello")`}, "/,/missing"}, // any -mdc
		{[]string{"-fdc", `status_code >= 400`}, "/,/admin"},
		{[]string{"-mdc", `contains(header, "PHP")`}, "/admin"},
		{[]string{"-td", "-mdc", `contains(tech, "WordPress")`}, "/admin"}, // evaluated after enrichment
		{[]string{"-td", "-fdc", `len(tech) > 0`}, "/,/missing"},
	} {
		got, code, stderr := paths(c.args...)
		if code != 0 || got != c.want {
			t.Errorf("%v: got %q (exit %d %s), want %q", c.args, got, code, stderr, c.want)
		}
	}
	if _, code, stderr := paths("-mdc", "stauts_code == 200"); code != ExitUsage || !strings.Contains(stderr, `unknown variable "stauts_code"`) {
		t.Errorf("typo must be rejected up front: %d %q", code, stderr)
	}
	if _, code, stderr := paths("-mdc", "status_code =="); code != ExitUsage || !strings.Contains(stderr, "-mdc") {
		t.Errorf("syntax error: %d %q", code, stderr)
	}
}

func TestVHostDetection(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		random := strings.HasPrefix(r.Host, "pulse-")
		switch r.URL.Path {
		case "/routed": // a different site for unknown names
			if random {
				w.WriteHeader(404)
				_, _ = fmt.Fprint(w, "<title>Default backend</title>")
				return
			}
			_, _ = fmt.Fprint(w, "<title>App</title>"+strings.Repeat("x", 500))
		case "/dynamic": // same site for any Host, but every response differs in size
			_, _ = fmt.Fprintf(w, "<title>Feed</title>%s", strings.Repeat("item ", int(n.Add(1)%7)*80))
		default: // same static page for any Host
			_, _ = fmt.Fprint(w, "<title>Static</title>hello")
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var out, errb syncBuf
	code := Main([]string{"-u", host, "-path", "/routed,/dynamic,/static", "-vhost", "-j", "-silent", "-nc"},
		Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := map[string]bool{}
	for _, r := range results(t, out.String()) {
		got[r.Path] = r.VHost
	}
	want := map[string]bool{"/routed": true, "/dynamic": false, "/static": false}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: vhost=%v, want %v", p, got[p], w)
		}
	}
}

func TestPipelineDetection(t *testing.T) {
	pipelining := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer pipelining.Close()
	// One response per connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer tlsSrv.Close()
	for target, want := range map[string]bool{
		strings.TrimPrefix(pipelining.URL, "http://"): true,
		tlsSrv.URL:         true, // over TLS
		ln.Addr().String(): false,
	} {
		var out, errb syncBuf
		Main([]string{"-u", target, "-pipeline", "-j", "-silent", "-nc"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
		rs := results(t, out.String())
		if len(rs) != 1 || rs[0].Pipeline != want {
			t.Errorf("%s: %+v (%s), want pipeline=%v", target, rs, errb.String(), want)
		}
	}
}

func TestRawRequestFile(t *testing.T) {
	type seen struct{ method, uri, custom, body string }
	got := make(chan seen, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.Method, r.RequestURI, r.Header.Get("X-Custom"), string(b)}
		_, _ = fmt.Fprint(w, "<title>api</title>")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	req := filepath.Join(t.TempDir(), "req.txt")
	if err := os.WriteFile(req, []byte("PUT /api/items?ids=1,2 HTTP/1.1\nHost: "+host+"\nX-Custom: from-file\nContent-Length: 99\n\n{\"a\":1}"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb syncBuf
	// No -u: the target is the file's Host.
	if code := Main([]string{"-request", req, "-j", "-silent", "-nc"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	s := <-got
	if s != (seen{"PUT", "/api/items?ids=1,2", "from-file", `{"a":1}`}) {
		t.Fatalf("server saw %+v", s)
	}
	if rs := results(t, out.String()); len(rs) != 1 || rs[0].Method != "PUT" || rs[0].Title != "api" {
		t.Fatalf("result %+v", rs)
	}
	if code := Main([]string{"-unsafe", "-u", host}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}); code != ExitUsage {
		t.Fatalf("-unsafe without -request must be rejected, got %d", code)
	}
}

func TestUnsafeSendsBytesUnchanged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Header name with a space before the colon and a lowercase method: Go's
	// client would refuse or normalize both.
	raw := "get /weird HTTP/1.1\r\nHost: x\r\nX-Spaced : 1\r\n\r\n"
	received := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		received <- string(buf[:n])
		_, _ = io.WriteString(c, "HTTP/1.1 418 I'm a teapot\r\nContent-Length: 22\r\n\r\n<title>teapot</title>\n")
	}()
	req := filepath.Join(t.TempDir(), "req.txt")
	if err := os.WriteFile(req, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb syncBuf
	code := Main([]string{"-request", req, "-unsafe", "-u", "http://" + ln.Addr().String(), "-j", "-silent", "-nc"},
		Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if r := <-received; r != raw {
		t.Fatalf("server received %q, want %q", r, raw)
	}
	if rs := results(t, out.String()); len(rs) != 1 || rs[0].StatusCode != 418 || rs[0].Title != "teapot" {
		t.Fatalf("result %+v", rs)
	}
}

func TestHelpPrintedOnce(t *testing.T) {
	var out, errb syncBuf
	if code := Main([]string{"-h"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if n := strings.Count(out.String(), "USAGE"); n != 1 || errb.String() != "" {
		t.Fatalf("help printed %d times to stdout; stderr %q", n, errb.String())
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("colors in help that is not on a terminal")
	}
	var errb2 syncBuf
	if code := Main([]string{"-no-such-flag"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb2}); code != ExitUsage ||
		strings.Contains(errb2.String(), "USAGE") || !strings.Contains(errb2.String(), "see pulse -h") {
		t.Fatalf("bad flag: exit %d %q", code, errb2.String())
	}
}

// -h shows a curated subset; every flag it names must exist, and -hh must
// list every documented flag.
func TestShortAndFullHelp(t *testing.T) {
	_, err := parse([]string{"-h"}, io.Discard)
	var h *helpRequest
	if !errors.As(err, &h) || h.full {
		t.Fatalf("-h: %v", err)
	}
	for _, sec := range shortHelp {
		for _, row := range sec.rows {
			for _, n := range row.names {
				if h.r.fs.Lookup(n) == nil {
					t.Errorf("short help names unknown flag -%s", n)
				}
			}
		}
		for _, cell := range sec.grid {
			if h.r.fs.Lookup(cell[0]) == nil {
				t.Errorf("short help names unknown flag -%s", cell[0])
			}
		}
	}
	var short strings.Builder
	h.r.shortUsage(&short, false)
	for _, l := range strings.Split(short.String(), "\n") {
		if len([]rune(l)) > 80 {
			t.Errorf("short help line wider than 80 columns: %q", l)
		}
	}

	var out syncBuf
	if code := Main([]string{"-hh"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: io.Discard}); code != ExitOK {
		t.Fatalf("-hh exit %d", code)
	}
	for _, g := range h.r.groups {
		for _, f := range g.flags {
			if !strings.Contains(out.String(), f.names) {
				t.Errorf("-hh misses %s", f.names)
			}
		}
	}
}

func TestTLSImpersonate(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "<title>%s</title>", r.Proto)
	})
	h1 := httptest.NewTLSServer(handler)
	defer h1.Close()
	h2 := httptest.NewUnstartedServer(handler)
	h2.EnableHTTP2 = true
	h2.StartTLS()
	defer h2.Close()
	for srv, want := range map[*httptest.Server]string{h1: "HTTP/1.1", h2: "HTTP/2.0"} {
		var out, errb syncBuf
		code := Main([]string{"-u", srv.URL, "-tls-impersonate", "-j", "-silent", "-nc"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
		rs := results(t, out.String())
		if code != 0 || len(rs) != 1 || rs[0].StatusCode != 200 || rs[0].Title != want || rs[0].HTTPVersion != want ||
			rs[0].TLS == nil || rs[0].Timing.TLS <= 0 {
			t.Errorf("%s: exit %d %+v %s", want, code, rs, errb.String())
		}
	}
	var out, errb syncBuf
	if code := Main([]string{"-u", "example.com", "-tls-impersonate", "-proxy", "http://127.0.0.1:1"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}); code != ExitUsage {
		t.Errorf("-tls-impersonate with -proxy must be rejected, got %d", code)
	}
}

func TestTLSImpersonateRetriesOnlyBlockedPages(t *testing.T) {
	// A "bot manager" that blocks clients whose ClientHello lacks GREASE
	// cipher suites (Go's does; Chrome's has them).
	var chrome atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !chrome.Load() {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "<title>Just a moment...</title>")
			return
		}
		_, _ = fmt.Fprint(w, "<title>Real site</title>")
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		grease := false
		for _, c := range h.CipherSuites {
			grease = grease || c&0x0f0f == 0x0a0a
		}
		chrome.Store(grease)
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	probe := func(args ...string) output.Result {
		var out, errb syncBuf
		Main(append([]string{"-u", srv.URL, "-j", "-silent", "-nc"}, args...), Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
		rs := results(t, out.String())
		if len(rs) != 1 {
			t.Fatalf("%v: %d results: %s", args, len(rs), errb.String())
		}
		return rs[0]
	}
	if r := probe(); r.StatusCode != 403 {
		t.Fatalf("without -tls-impersonate the block page stays: %+v", r)
	}
	r := probe("-tls-impersonate")
	if r.StatusCode != 200 || r.Title != "Real site" || !slices.Contains(r.Warnings, "tls_impersonated") {
		t.Fatalf("blocked page must be retried with Chrome's fingerprint: %+v", r)
	}
}

// A second Ctrl+C aborts in-flight probes; they must not count as done.
func TestDoubleInterruptKeepsAbortedLinesOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()
	list := filepath.Join(dir, "in.txt")
	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf("%s/d%d", host, i))
	}
	_ = os.WriteFile(list, []byte(strings.Join(lines, "\n")), 0o644)
	resume := filepath.Join(dir, "resume.json")
	sigs := make(chan os.Signal, 2)
	go func() {
		time.Sleep(200 * time.Millisecond)
		sigs <- os.Interrupt
		time.Sleep(100 * time.Millisecond)
		sigs <- os.Interrupt
	}()
	var out syncBuf
	start := time.Now()
	code, stderr := run(t, []string{"-l", list, "-t", "4", "-rl", "0", "-j", "-probe", "-resume", resume}, &out, sigs)
	if code != ExitInterrupted {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("second Ctrl+C must abort in-flight probes quickly: %v", d)
	}
	cp, err := engine.LoadCheckpoint(resume)
	if err != nil || cp.NextLine != 0 {
		t.Fatalf("aborted probes must not move the resume point: %+v %v", cp, err)
	}
	if rs := results(t, out.String()); len(rs) != 0 {
		t.Fatalf("aborted probes must not be reported as results: %d", len(rs))
	}
}

// After one Ctrl+C only the probes already started finish; queued ones are
// left for -resume, and nothing is lost or duplicated.
func TestInterruptStopsPromptlyAndResumesExactly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()
	list := filepath.Join(dir, "in.txt")
	var lines []string
	for i := 0; i < 60; i++ {
		lines = append(lines, fmt.Sprintf("%s/q%d", host, i))
	}
	_ = os.WriteFile(list, []byte(strings.Join(lines, "\n")), 0o644)
	resume := filepath.Join(dir, "resume.json")
	args := []string{"-l", list, "-t", "3", "-ch", "0", "-rl", "0", "-j", "-resume", resume}
	sigs := make(chan os.Signal, 1)
	go func() { time.Sleep(450 * time.Millisecond); sigs <- os.Interrupt }()
	var out1 syncBuf
	start := time.Now()
	if code, stderr := run(t, args, &out1, sigs); code != ExitInterrupted {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("one Ctrl+C must stop after the in-flight probes, took %v", d)
	}
	var out2 syncBuf
	if code, stderr := run(t, args, &out2, nil); code != ExitOK {
		t.Fatalf("resume exit %d: %s", code, stderr)
	}
	seen := map[string]int{}
	for _, r := range append(results(t, out1.String()), results(t, out2.String())...) {
		seen[r.Path]++
	}
	for i := 0; i < 60; i++ {
		if n := seen[fmt.Sprintf("/q%d", i)]; n < 1 {
			t.Fatalf("/q%d lost across interrupt+resume", i)
		}
	}
}

// With -adaptive a host starts at one request at a time and gains slots as
// it answers; parked requests for it must then really run in parallel.
func TestAdaptiveSlowStartReachesParallelism(t *testing.T) {
	var cur, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		cur.Add(-1)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var paths []string
	for i := 0; i < 40; i++ {
		paths = append(paths, fmt.Sprintf("/p%d", i))
	}
	var out, errb syncBuf
	code := Main([]string{"-u", host, "-path", strings.Join(paths, ","), "-ch", "8", "-adaptive", "-j", "-silent", "-nc"},
		Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	if code != 0 || len(results(t, out.String())) != 40 {
		t.Fatalf("exit %d, %d results: %s", code, len(results(t, out.String())), errb.String())
	}
	if p := peak.Load(); p < 4 || p > 8 {
		t.Fatalf("peak concurrency %d, want slow start to reach 4..8 (cap -ch 8)", p)
	}
}

func TestURLCredentialsSentAsBasicAuthNotPrinted(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		got <- u + ":" + p
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var out, errb syncBuf
	Main([]string{"-u", "http://alice:s3cret@" + host + "/x", "-j", "-silent", "-nc"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	if c := <-got; c != "alice:s3cret" {
		t.Fatalf("server got credentials %q", c)
	}
	if strings.Contains(out.String(), "s3cret") && !strings.Contains(out.String(), `"input"`) {
		t.Fatalf("password leaked: %s", out.String())
	}
	rs := results(t, out.String())
	if len(rs) != 1 || strings.Contains(rs[0].URL, "s3cret") {
		t.Fatalf("URL must not carry the password: %+v", rs)
	}
}

func TestUnsafeURLAndDNSClass(t *testing.T) {
	req := filepath.Join(t.TempDir(), "req.txt")
	_ = os.WriteFile(req, []byte("GET /deep/path HTTP/1.1\r\nHost: x\r\n\r\n"), 0o644)
	var out, errb syncBuf
	Main([]string{"-request", req, "-unsafe", "-u", "http://nonexistent.invalid", "-r", pulseTestDNSNX(t), "-j", "-probe", "-silent", "-nc", "-timeout", "3s"},
		Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	rs := results(t, out.String())
	if len(rs) != 1 || rs[0].Error == nil || rs[0].Error.Class != "dns_nxdomain" || !strings.HasSuffix(rs[0].URL, "/deep/path") {
		t.Fatalf("got %+v (%s)", rs, errb.String())
	}
}

// pulseTestDNSNX answers every query with NXDOMAIN.
func pulseTestDNSNX(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: dnsmessage.RCodeNameError})
			_ = b.StartQuestions()
			_ = b.Question(q)
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestNonUTF8BodyMatchesAndIsDecoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=windows-1251")
		_, _ = w.Write([]byte("<title>\xcf\xf0\xe8\xe2\xe5\xf2</title>\xcf\xf0\xe8\xe2\xe5\xf2 \xec\xe8\xf0")) // "Привет мир"
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var out, errb syncBuf
	Main([]string{"-u", host, "-ms", "привет мир", "-irr", "-j", "-silent", "-nc"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	rs := results(t, out.String())
	if len(rs) != 1 || !strings.Contains(rs[0].Body, "Привет мир") || strings.ContainsRune(rs[0].Body, '�') {
		t.Fatalf("got %+v %s", rs, errb.String())
	}
}

func TestMalformedHeadersStillAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nServer: \x1b]0;evil\x07nginx\r\nContent-Length: 18\r\n\r\n<title>odd</title>")
			}(c)
		}
	}()
	var out, errb syncBuf
	Main([]string{"-u", ln.Addr().String(), "-j", "-probe", "-silent", "-nc"}, Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	rs := results(t, out.String())
	if len(rs) != 1 || rs[0].Failed || rs[0].StatusCode != 200 || rs[0].Title != "odd" || !slices.Contains(rs[0].Warnings, "malformed_headers") {
		t.Fatalf("got %+v (%s)", rs, errb.String())
	}
	var txt syncBuf
	Main([]string{"-u", ln.Addr().String(), "-server", "-silent", "-nc"}, Env{Stdin: strings.NewReader(""), Stdout: &txt, Stderr: &errb})
	if strings.ContainsAny(txt.String(), "\x1b\x07") {
		t.Fatalf("control characters reached the terminal: %q", txt.String())
	}
}

func TestCompatFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			_, _ = fmt.Fprint(w, "<title>404 Not Found</title>")
		case "/slow":
			time.Sleep(300 * time.Millisecond)
			_, _ = fmt.Fprint(w, "<title>slow</title>")
		default:
			w.Header().Set("X-Contact", "admin@example.org")
			_, _ = fmt.Fprintf(w, "<title>Home</title>   Visit   https://cdn.example.com/a.js from 10.1.2.3 <!-- %s -->", r.UserAgent())
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	runJ := func(args ...string) ([]output.Result, int, string) {
		var out, errb syncBuf
		code := Main(append([]string{"-u", host, "-j", "-silent", "-nc"}, args...), Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
		return results(t, out.String()), code, errb.String()
	}

	rs, code, stderr := runJ("-duc", "-stream", "-tls-grab", "-include-chain", "-nfs", "-bp=12", "-ep", "url,ipv4,mail", "-er", `Visit\s+\S+`, "-hash", "sha512,simhash")
	if code != 0 || len(rs) != 1 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	r := rs[0]
	if r.BodyPreview != "<title>Home<" || r.Extracts["url"][0] != "https://cdn.example.com/a.js" ||
		r.Extracts["ipv4"][0] != "10.1.2.3" || r.Extracts["mail"][0] != "admin@example.org" || len(r.Extracts[`Visit\s+\S+`]) != 1 ||
		len(r.Hashes["body_sha512"]) != 128 || r.Hashes["body_simhash"] == "" || r.Hashes["header_sha512"] == "" {
		t.Fatalf("result %+v", r)
	}
	if rs, _, _ := runJ("-bp"); len(rs) != 1 || rs[0].BodyPreview == "" {
		t.Fatalf("-bp without value: %+v", rs)
	}
	if rs, _, _ := runJ("-path", "/,/missing", "-fep"); len(rs) != 1 || rs[0].Path != "/" {
		t.Fatalf("-fep: %+v", rs)
	}
	if rs, _, _ := runJ("-path", "/,/slow", "-mrt", "> 0.2"); len(rs) != 1 || rs[0].Path != "/slow" {
		t.Fatalf("-mrt: %+v", rs)
	}
	if rs, _, _ := runJ("-path", "/,/slow", "-frt", ">= 0.2"); len(rs) != 1 || rs[0].Path != "/" {
		t.Fatalf("-frt: %+v", rs)
	}
	// Same page from the same IP under two paths: -fd keeps the first.
	if rs, _, _ := runJ("-path", "/a,/b", "-fd", "-t", "1"); len(rs) != 1 {
		t.Fatalf("-fd kept %d", len(rs))
	}
	_, srvPort, _ := net.SplitHostPort(host)
	for _, ex := range []string{"127.0.0.1", "127.0.0.0/8", "private-ips", `^127\.`, srvPort} {
		if rs, code, _ := runJ("-e", ex); code != 0 || len(rs) != 0 {
			t.Fatalf("-e %s: exit %d, %d results", ex, code, len(rs))
		}
	}
	if rs, _, _ := runJ("-ldp"); len(rs) != 1 {
		t.Fatalf("-ldp: %+v", rs)
	}
	agents := map[string]bool{}
	for i := 0; i < 12; i++ {
		rs, _, _ := runJ("-random-agent", "-er", `Mozilla[^>]+`)
		if len(rs) == 1 {
			for _, m := range rs[0].Extracts[`Mozilla[^>]+`] {
				agents[m] = true
			}
		}
	}
	if len(agents) < 2 {
		t.Fatalf("-random-agent sent %d distinct agents", len(agents))
	}
	// Stray values no longer become targets.
	for _, args := range [][]string{{"-tlsi", "chrome"}, {"-bp", "200"}, {"-ep", "url", "-silent", "extra"}} {
		if _, code, stderr := runJ(args...); code != ExitUsage || !strings.Contains(stderr, "unexpected argument") && !strings.Contains(stderr, "after a target") {
			t.Errorf("%v: exit %d %q", args, code, stderr)
		}
	}
	if _, code, _ := runJ("-tlsi=chrome"); code != 0 {
		t.Errorf("-tlsi=chrome must parse")
	}
	if _, code, stderr := runJ("-resume", "-l"); code != ExitUsage {
		t.Errorf("-resume -l: exit %d %q", code, stderr)
	}
}
