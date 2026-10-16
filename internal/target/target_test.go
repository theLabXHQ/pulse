package target

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in                 string
		scheme, host, path string
		port               int
		wantErr            bool
	}{
		{in: "example.com", host: "example.com"},
		{in: "  EXAMPLE.com.  ", host: "example.com"},
		{in: "example.com:8443", host: "example.com", port: 8443},
		{in: "https://example.com", scheme: "https", host: "example.com"},
		{in: "http://example.com:8080/a/b?x=1", scheme: "http", host: "example.com", port: 8080, path: "/a/b?x=1"},
		{in: "example.com/admin", host: "example.com", path: "/admin"},
		{in: "*.example.com", host: "example.com"},
		{in: ".example.com", host: "example.com"},
		{in: "192.0.2.1", host: "192.0.2.1"},
		{in: "[2001:db8::1]:8080", host: "2001:db8::1", port: 8080},
		{in: "http://[::ffff:192.0.2.1]/", scheme: "http", host: "192.0.2.1", path: ""},
		{in: "bücher.example", host: "xn--bcher-kva.example"},
		{in: "under_score.example.com", host: "under_score.example.com"},
		{in: "ftp://example.com", wantErr: true},
		{in: "example.com:99999", wantErr: true},
		{in: "exa mple.com", wantErr: true},
		{in: "", wantErr: true},
		{in: "# comment", wantErr: true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %+v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) error: %v", c.in, err)
			continue
		}
		if got.Scheme != c.scheme || got.Host != c.host || got.Port != c.port || got.Path != c.path {
			t.Errorf("Parse(%q) = %+v, want scheme=%q host=%q port=%d path=%q", c.in, got, c.scheme, c.host, c.port, c.path)
		}
	}
}

func TestKeyDedupesEquivalentInputs(t *testing.T) {
	a, _ := Parse("Example.com")
	b, _ := Parse("example.com.")
	c, _ := Parse("example.com:443")
	if a.Key() != b.Key() {
		t.Fatalf("expected equal keys: %q vs %q", a.Key(), b.Key())
	}
	if a.Key() == c.Key() {
		t.Fatalf("explicit port must produce a distinct key")
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("80, 443,8000-8002,http:8080,https:8443,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []PortSpec{{80, ""}, {443, ""}, {8000, ""}, {8001, ""}, {8002, ""}, {8080, "http"}, {8443, "https"}}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	for _, bad := range []string{"", "0", "70000", "10-5", "ftp:21", "a-b"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q) should fail", bad)
		}
	}
}

func TestSchemeOrder(t *testing.T) {
	for port, first := range map[int]string{0: "https", 443: "https", 80: "http", 8080: "http", 8443: "https", 18443: "https", 4443: "https", 8444: "http", 22: "https", 993: "https"} {
		if got := SchemeOrder(port)[0]; got != first {
			t.Errorf("SchemeOrder(%d)[0] = %s, want %s", port, got, first)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	var got []netip.Addr
	if err := ExpandCIDR("192.0.2.4/30", func(a netip.Addr) bool { got = append(got, a); return true }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].String() != "192.0.2.4" || got[3].String() != "192.0.2.7" {
		t.Fatalf("unexpected expansion %v", got)
	}
	n := 0
	_ = ExpandCIDR("10.0.0.0/8", func(netip.Addr) bool { n++; return n < 10 })
	if n != 10 {
		t.Fatalf("early stop not honoured: %d", n)
	}
	if err := ExpandCIDR("2001:db8::/64", func(netip.Addr) bool { return true }); err == nil {
		t.Fatal("huge IPv6 prefix must be rejected")
	}
	if !IsCIDR("10.0.0.0/24") || IsCIDR("example.com/24") || IsCIDR("http://10.0.0.0/24") {
		t.Fatal("IsCIDR misclassifies")
	}
}

func TestBuildURL(t *testing.T) {
	cases := map[string]string{
		BuildURL("https", "example.com", 443, ""):   "https://example.com/",
		BuildURL("http", "example.com", 8080, "/x"): "http://example.com:8080/x",
		BuildURL("http", "2001:db8::1", 80, "a"):    "http://[2001:db8::1]/a",
		BuildURL("https", "2001:db8::1", 8443, "/"): "https://[2001:db8::1]:8443/",
		BuildURL("http", "example.com", 0, "/?q=1"): "http://example.com/?q=1",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}

func TestParseEdgeCases(t *testing.T) {
	for in, want := range map[string]string{
		"::1":                              "|::1|0|",
		"::ffff:127.0.0.1":                 "|127.0.0.1|0|",
		"HTTP://Example.COM/":              "http|example.com|0|",
		"http://user:p%40ss@example.com/x": "http|example.com|0|/x",
	} {
		tg, err := Parse(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got := tg.Scheme + "|" + tg.Host + "|" + strconv.Itoa(tg.Port) + "|" + tg.Path; got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	tg, _ := Parse("http://user:p%40ss@example.com/x")
	if tg.Auth != "user:p@ss" {
		t.Errorf("auth %q", tg.Auth)
	}
	a, _ := Parse("http://example.com")
	b, _ := Parse("HTTP://example.com/")
	if a.Key() != b.Key() {
		t.Errorf("trailing slash and scheme case must dedupe: %s vs %s", a.Key(), b.Key())
	}
	for _, bad := range []string{"a..b.com", strings.Repeat("x", 64) + ".com"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}
