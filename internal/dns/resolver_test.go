package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers A queries for *.ok.test with 192.0.2.7, TXT queries with
// two records (the second split in two strings) and NXDOMAIN otherwise.
func fakeDNS(t *testing.T, delay time.Duration) (addr string, queries *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	queries = new(atomic.Int64)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			go func() {
				time.Sleep(delay)
				var p dnsmessage.Parser
				h, err := p.Start(req)
				if err != nil {
					return
				}
				q, err := p.Question()
				if err != nil {
					return
				}
				queries.Add(1)
				ok := strings.HasSuffix(q.Name.String(), ".ok.test.")
				rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}
				if !ok {
					rh.RCode = dnsmessage.RCodeNameError
				}
				b := dnsmessage.NewBuilder(nil, rh)
				_ = b.StartQuestions()
				_ = b.Question(q)
				_ = b.StartAnswers()
				if ok && q.Type == dnsmessage.TypeA {
					_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
						dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}})
				}
				if ok && q.Type == dnsmessage.TypeTXT {
					hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
					_ = b.TXTResource(hdr, dnsmessage.TXTResource{TXT: []string{"13335 | 104.16.0.0/13 | US"}})
					_ = b.TXTResource(hdr, dnsmessage.TXTResource{TXT: []string{"part1", "part2"}})
				}
				out, _ := b.Finish()
				_, _ = pc.WriteTo(out, from)
			}()
		}
	}()
	return pc.LocalAddr().String(), queries
}

func TestCachingAndCoalescing(t *testing.T) {
	addr, queries := fakeDNS(t, 50*time.Millisecond)
	r := New(Options{Servers: []string{addr}})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ips, err := r.Lookup(context.Background(), "www.ok.test")
			if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.7" {
				t.Errorf("lookup: %v %v", ips, err)
			}
		}()
	}
	wg.Wait()
	if _, err := r.Lookup(context.Background(), "WWW.OK.TEST."); err != nil {
		t.Fatal(err)
	}
	if r.Lookups() != 1 {
		t.Fatalf("51 lookups of one name must hit the network once, got %d", r.Lookups())
	}
	// The Go resolver asks A and AAAA; both count as one logical lookup.
	if q := queries.Load(); q > 2 {
		t.Fatalf("expected at most 2 wire queries, got %d", q)
	}
}

func TestNegativeAnswersAreClassifiedAndCached(t *testing.T) {
	addr, _ := fakeDNS(t, 0)
	r := New(Options{Servers: []string{addr}})
	_, err := r.Lookup(context.Background(), "missing.test")
	var de *net.DNSError
	if !errors.As(err, &de) || !de.IsNotFound {
		t.Fatalf("want NXDOMAIN DNSError, got %v", err)
	}
	_, _ = r.Lookup(context.Background(), "missing.test")
	if r.Lookups() != 1 {
		t.Fatalf("negative answer not cached: %d lookups", r.Lookups())
	}
}

func TestIPLiteralsSkipResolution(t *testing.T) {
	r := New(Options{Servers: []string{"127.0.0.1:1"}})
	ips, err := r.Lookup(context.Background(), "::ffff:10.0.0.1")
	if err != nil || ips[0].String() != "10.0.0.1" || r.Lookups() != 0 {
		t.Fatalf("got %v %v", ips, err)
	}
}

func TestCallerCancellationDoesNotPoisonCache(t *testing.T) {
	addr, _ := fakeDNS(t, 100*time.Millisecond)
	r := New(Options{Servers: []string{addr}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := r.Lookup(ctx, "a.ok.test"); err == nil {
		t.Fatal("expected caller timeout")
	}
	time.Sleep(150 * time.Millisecond)
	ips, err := r.Lookup(context.Background(), "a.ok.test")
	if err != nil || len(ips) != 1 {
		t.Fatalf("answer for patient callers must survive: %v %v", ips, err)
	}
}

// lossyProxy forwards UDP to upstream but silently drops the first drop packets.
func lossyProxy(t *testing.T, upstream string, drop int64) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	up, err := net.Dial("udp", upstream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	var client atomic.Value
	var seen atomic.Int64
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			client.Store(from)
			if seen.Add(1) <= drop {
				continue
			}
			_, _ = up.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			if from, ok := client.Load().(net.Addr); ok {
				_, _ = pc.WriteTo(buf[:n], from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestLostPacketsAreRetransmittedQuickly(t *testing.T) {
	addr, _ := fakeDNS(t, 0)
	// Both the A and the AAAA query are lost once.
	r := New(Options{Servers: []string{lossyProxy(t, addr, 2)}, Timeout: 5 * time.Second})
	start := time.Now()
	ips, err := r.Lookup(context.Background(), "x.ok.test")
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.7" {
		t.Fatalf("got %v %v", ips, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a lost packet must cost one short RTO, not a resolver timeout: %v", d)
	}
}

func TestSilentServerTimesOut(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // never answers
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	r := New(Options{Servers: []string{pc.LocalAddr().String()}, Timeout: 300 * time.Millisecond})
	_, err = r.Lookup(context.Background(), "x.ok.test")
	var de *net.DNSError
	if !errors.As(err, &de) || !de.IsTimeout || de.Name != "x.ok.test" {
		t.Fatalf("want timeout DNSError, got %#v", err)
	}
}

// aOnlyDNS answers A queries for *.ok.test and silently drops everything else,
// like resolvers that ignore AAAA.
func aOnlyDNS(t *testing.T) string {
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
			if err != nil || q.Type != dnsmessage.TypeA {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}})
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestUnansweredAAAADoesNotStallLookup(t *testing.T) {
	r := New(Options{Servers: []string{aOnlyDNS(t)}, Timeout: 5 * time.Second})
	start := time.Now()
	ips, err := r.Lookup(context.Background(), "x.ok.test")
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
		t.Fatalf("got %v %v", ips, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("an unanswered AAAA query must not hold the A answer: %v", d)
	}
}

// silentSystem points r's system resolver at a server that never answers.
func silentSystem(t *testing.T, r *CachingResolver) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	addr := pc.LocalAddr().String()
	r.net = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", addr)
	}}
	u, err := newUDPClient([]netip.AddrPort{netip.MustParseAddrPort(addr)}, false, r.net)
	if err != nil {
		t.Fatal(err)
	}
	r.sys = &systemResolver{cfg: &systemConfig{ndots: 1, hosts: map[string][]netip.Addr{}}, udp: u}
}

func TestFallbackWhenSystemResolverIsDeadAtStart(t *testing.T) {
	good, _ := fakeDNS(t, 0)
	var reasons []string
	r := New(Options{Fallback: []string{good}, Timeout: 300 * time.Millisecond,
		OnFallback: func(reason string) { reasons = append(reasons, reason) }})
	silentSystem(t, r)
	r.CheckSystem(200 * time.Millisecond)
	r.CheckSystem(200 * time.Millisecond) // idempotent
	if !r.UsingFallback() || len(reasons) != 1 {
		t.Fatalf("fallback=%v reasons=%v", r.UsingFallback(), reasons)
	}
	ips, err := r.Lookup(context.Background(), "a.ok.test")
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.7" {
		t.Fatalf("got %v %v", ips, err)
	}
}

func TestFallbackAfterConsecutiveTimeouts(t *testing.T) {
	good, _ := fakeDNS(t, 0)
	r := New(Options{Fallback: []string{good}, Timeout: 50 * time.Millisecond})
	silentSystem(t, r)
	// Before the switch, each name the system resolver drops is answered by
	// the fallback: nothing is lost while it is flaky.
	for i := 0; i < fallbackAfter-1; i++ {
		if ips, err := r.Lookup(context.Background(), fmt.Sprintf("h%d.ok.test", i)); err != nil || len(ips) != 1 {
			t.Fatalf("h%d: %v %v", i, ips, err)
		}
	}
	if r.UsingFallback() {
		t.Fatal("switched too early")
	}
	if ips, err := r.Lookup(context.Background(), "last.ok.test"); err != nil || len(ips) != 1 || !r.UsingFallback() {
		t.Fatalf("threshold lookup: %v %v fallback=%v", ips, err, r.UsingFallback())
	}
}

func TestNoFallbackWithExplicitServers(t *testing.T) {
	good, _ := fakeDNS(t, 0)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // silent explicit server
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	r := New(Options{Servers: []string{pc.LocalAddr().String()}, Fallback: []string{good}, Timeout: 100 * time.Millisecond})
	r.CheckSystem(100 * time.Millisecond)
	if _, err := r.Lookup(context.Background(), "a.ok.test"); err == nil || r.UsingFallback() {
		t.Fatal("explicit -r servers must never be replaced by the fallback")
	}
}

func TestLookupTXT(t *testing.T) {
	good, _ := fakeDNS(t, 0)
	r := New(Options{Servers: []string{good}, Timeout: time.Second})
	recs, err := r.LookupTXT(context.Background(), "x.ok.test")
	if err != nil || len(recs) != 2 || recs[0] != "13335 | 104.16.0.0/13 | US" || recs[1] != "part1part2" {
		t.Fatalf("got %q %v", recs, err)
	}
	var de *net.DNSError
	if _, err := r.LookupTXT(context.Background(), "nope.test"); !errors.As(err, &de) || !de.IsNotFound {
		t.Fatalf("NXDOMAIN: %v", err)
	}
}

// A TXT query the system resolver drops is answered by the fallback, as
// address lookups are (-asn must not lose IPs while the system DNS is flaky).
func TestLookupTXTFallsBackPerName(t *testing.T) {
	good, _ := fakeDNS(t, 0)
	r := New(Options{Fallback: []string{good}, Timeout: 300 * time.Millisecond})
	silentSystem(t, r)
	recs, err := r.LookupTXT(context.Background(), "x.ok.test")
	if err != nil || len(recs) != 2 {
		t.Fatalf("got %q %v", recs, err)
	}
	if r.UsingFallback() {
		t.Fatal("one dropped TXT query must not switch every lookup to the fallback")
	}
	if chain, err := r.LookupCNAME(context.Background(), "x.ok.test"); err != nil || len(chain) != 0 {
		t.Fatalf("CNAME via fallback: %v %v", chain, err)
	}
}

// noDataDNS answers every query with NOERROR and no records, like a
// resolver that got an empty answer from one of a domain's broken
// authoritative servers.
func noDataDNS(t *testing.T) string {
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
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestNoDataAsksNextServer(t *testing.T) {
	good, _ := fakeDNS(t, 0)
	c, err := newUDPClient(parseServers([]string{noDataDNS(t), good}), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ { // whichever server a lookup starts with
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addrs, err := c.LookupNetIP(ctx, "host.ok.test")
		cancel()
		if err != nil || len(addrs) != 1 {
			t.Fatalf("lookup %d: %v %v", i, addrs, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.LookupNetIP(ctx, "gone.test"); err == nil {
		t.Fatal("NXDOMAIN resolved")
	} else if de, ok := err.(*net.DNSError); !ok || !de.IsNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}
