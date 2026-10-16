package cdn

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"math/rand"
	"net/netip"
	"testing"
)

func embedded(t *testing.T) map[string]map[string][]string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(rangesGz))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]map[string][]string
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

// oracle is the obvious implementation: per kind in order, the longest
// containing prefix wins, ties by provider name.
func oracle(data map[string]map[string][]string, ip netip.Addr) (Match, bool) {
	ip = ip.Unmap()
	for _, kind := range Kinds {
		best, bestBits := "", -1
		for name, cidrs := range data[kind] {
			for _, c := range cidrs {
				p := netip.MustParsePrefix(c)
				if p.Contains(ip) && (p.Bits() > bestBits || (p.Bits() == bestBits && name < best)) {
					best, bestBits = name, p.Bits()
				}
			}
		}
		if bestBits >= 0 {
			return Match{Name: best, Type: kind}, true
		}
	}
	return Match{}, false
}

func TestLookupMatchesOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	data := embedded(t)
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	var all []netip.Prefix
	for _, providers := range data {
		for _, cidrs := range providers {
			for _, c := range cidrs {
				all = append(all, netip.MustParsePrefix(c))
			}
		}
	}
	var ips []netip.Addr
	for i := 0; i < 600; i++ {
		p := all[rng.Intn(len(all))]
		ips = append(ips, p.Addr(), last(p), random(rng, p), p.Addr().Prev(), last(p).Next())
	}
	for i := 0; i < 300; i++ { // mostly not covered
		var b [4]byte
		rng.Read(b[:])
		ips = append(ips, netip.AddrFrom4(b))
	}
	ips = append(ips, netip.MustParseAddr("::ffff:104.16.0.1")) // IPv4-mapped
	matched := 0
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		want, wok := oracle(data, ip)
		got, gok := db.Lookup(ip)
		if want != got || wok != gok {
			t.Errorf("Lookup(%s) = %v %v, want %v %v", ip, got, gok, want, wok)
		}
		if wok {
			matched++
		}
	}
	if matched < len(ips)/2 {
		t.Fatalf("only %d/%d samples matched; sampling is broken", matched, len(ips))
	}
}

func last(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	host := len(a)*8 - p.Bits()
	for i := len(a) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		a[i] |= byte(1<<n - 1)
		host -= n
	}
	r, _ := netip.AddrFromSlice(a)
	return r
}

func random(rng *rand.Rand, p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	host := len(a)*8 - p.Bits()
	for i := len(a) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		a[i] |= byte(rng.Intn(1 << n))
		host -= n
	}
	r, _ := netip.AddrFromSlice(a)
	return r
}

func TestKnownAddresses(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]Match{
		"104.16.0.1":   {Name: "cloudflare", Type: "waf"}, // cdncheck lists Cloudflare as waf
		"127.0.0.1":    {},
		"192.168.1.10": {},
	} {
		got, ok := db.Lookup(netip.MustParseAddr(ip))
		if got != want || ok != (want != Match{}) {
			t.Errorf("Lookup(%s) = %v %v, want %v", ip, got, ok, want)
		}
	}
	if _, ok := db.Lookup(netip.Addr{}); ok {
		t.Error("invalid address must not match")
	}
}

func TestMostSpecificPrefixWins(t *testing.T) {
	db, err := build(map[string]map[string][]string{
		"cdn": {"wide": {"10.0.0.0/8", "2001:db8::/32"}, "narrow": {"10.1.2.0/24", "2001:db8:1::/48"}, "same": {"10.1.2.0/24"}},
		"waf": {"edge": {"10.1.2.3/32"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]Match{
		"10.9.9.9":        {Name: "wide", Type: "cdn"},
		"10.1.2.3":        {Name: "narrow", Type: "cdn"}, // cdn before waf; narrow < same by name
		"2001:db8:1::5":   {Name: "narrow", Type: "cdn"},
		"2001:db8:ffff::": {Name: "wide", Type: "cdn"},
	} {
		if got, _ := db.Lookup(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Lookup(%s) = %v, want %v", ip, got, want)
		}
	}
}

func BenchmarkLookup(b *testing.B) {
	db, err := Default()
	if err != nil {
		b.Fatal(err)
	}
	ips := []netip.Addr{netip.MustParseAddr("104.16.0.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700::1")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.Lookup(ips[i%len(ips)])
	}
}

func BenchmarkLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := decode(rangesGz); err != nil {
			b.Fatal(err)
		}
	}
}
