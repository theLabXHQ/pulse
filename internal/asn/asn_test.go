package asn

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const tsv = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n" +
	"104.16.0.0\t104.23.255.255\t13335\tUS\tCLOUDFLARENET\n" +
	"2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET\n"

func TestFileDB(t *testing.T) {
	db, err := parseTSV(strings.NewReader(tsv))
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{
		"1.0.0.7":         "13335 CLOUDFLARENET US 1.0.0.0/24",
		"8.8.8.8":         "15169 GOOGLE US 8.8.8.0/24",
		"104.20.1.1":      "13335 CLOUDFLARENET US 104.16.0.0/13",
		"::ffff:8.8.8.8":  "15169 GOOGLE US 8.8.8.0/24",
		"2606:4700::1111": "13335 CLOUDFLARENET US 2606:4700::/32",
		"1.0.2.1":         "", // not routed
		"9.9.9.9":         "",
		"2001:db8::1":     "",
	} {
		info, err := db.Lookup(context.Background(), netip.MustParseAddr(ip))
		if err != nil {
			t.Fatal(err)
		}
		if got := describe(info); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
}

func describe(i *Info) string {
	if i == nil {
		return ""
	}
	return strings.Join([]string{strconv.Itoa(i.Number), i.Name, i.Country, strings.Join(i.Ranges, ",")}, " ")
}

func TestRangeToCIDRs(t *testing.T) {
	for _, c := range []struct{ start, end, want string }{
		{"1.0.1.0", "1.0.3.255", "1.0.1.0/24,1.0.2.0/23"},
		{"10.0.0.0", "10.255.255.255", "10.0.0.0/8"},
		{"10.0.0.5", "10.0.0.5", "10.0.0.5/32"},
		{"255.255.255.0", "255.255.255.255", "255.255.255.0/24"},
		{"2001:db8::", "2001:db8::ffff", "2001:db8::/112"},
	} {
		got := strings.Join(rangeToCIDRs(netip.MustParseAddr(c.start), netip.MustParseAddr(c.end)), ",")
		if got != c.want {
			t.Errorf("%s-%s = %s, want %s", c.start, c.end, got, c.want)
		}
	}
}

func TestCymru(t *testing.T) {
	var calls atomic.Int64
	v6name := originName(netip.MustParseAddr("2606:4700::1111"))
	if !strings.HasPrefix(v6name, "1.1.1.1.0.0.0.0.") || !strings.HasSuffix(v6name, ".0.0.7.4.6.0.6.2.origin6.asn.cymru.com") {
		t.Fatalf("bad v6 origin name %s", v6name)
	}
	txt := func(_ context.Context, name string) ([]string, error) {
		calls.Add(1)
		switch name {
		case "1.0.16.104.origin.asn.cymru.com", "9.9.16.104.origin.asn.cymru.com":
			return []string{"13335 | 104.16.0.0/13 | US | arin | 2014-03-28", "13335 | 104.16.0.0/12 | US | arin | 2014-03-28"}, nil
		case "AS13335.asn.cymru.com":
			return []string{"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"}, nil
		case v6name:
			return []string{"13335 | 2606:4700::/32 | US | arin | 2011-11-01"}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	c := NewCymru(txt)
	ctx := context.Background()
	info, err := c.Lookup(ctx, netip.MustParseAddr("104.16.0.1"))
	if err != nil || describe(info) != "13335 CLOUDFLARENET US 104.16.0.0/13" {
		t.Fatalf("got %q %v", describe(info), err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("want origin + name queries, got %d", n)
	}
	// Same /24: served from cache, no query.
	if info, _ := c.Lookup(ctx, netip.MustParseAddr("104.16.0.200")); describe(info) == "" || calls.Load() != 2 {
		t.Fatalf("same /24 must hit the cache (calls %d)", calls.Load())
	}
	if info, _ := c.Lookup(ctx, netip.MustParseAddr("2606:4700::1111")); describe(info) != "13335 CLOUDFLARENET US 2606:4700::/32" || calls.Load() != 3 {
		t.Fatalf("v6: %q, calls %d (AS name must come from cache)", describe(info), calls.Load())
	}
	if info, err := c.Lookup(ctx, netip.MustParseAddr("192.0.2.1")); info != nil || err != nil {
		t.Fatalf("unannounced: %v %v", info, err)
	}
}
