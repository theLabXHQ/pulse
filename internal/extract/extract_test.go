package extract

import (
	"net/http"
	"strings"
	"testing"
)

func TestTitle(t *testing.T) {
	cases := []struct{ body, ct, want string }{
		{"<html><head><title>Hello</title></head></html>", "text/html", "Hello"},
		{"<title>\n  Multi \t line\n title </title>", "text/html", "Multi line title"},
		{"<TITLE>Tom &amp; Jerry &#39;s</TITLE>", "text/html", "Tom & Jerry 's"},
		{"<html><body><svg><title>icon</title></svg><title>Real</title></body></html>", "text/html", "Real"},
		{"<html><head></head><body>no title</body></html>", "text/html", ""},
		{"<title>unterminated", "text/html", "unterminated"},
		// GBK-encoded "中文" declared in Content-Type.
		{"<title>\xd6\xd0\xce\xc4</title>", "text/html; charset=gbk", "中文"},
		// Windows-1251 "Привет" declared via <meta>.
		{"<meta charset=\"windows-1251\"><title>\xcf\xf0\xe8\xe2\xe5\xf2</title>", "text/html", "Привет"},
		// Bot-challenge pages (imperva.com) put the title inside <noscript>.
		{"<html><head>\r\n<noscript>\r\n<title>Pardon Our Interruption</title>\r\n</noscript>", "text/html", "Pardon Our Interruption"},
		{"<head><noscript><img src=x></noscript><title>After</title></head>", "text/html", "After"},
		{"<head><noscript><svg><title>icon</title></svg></noscript><title>Real</title></head>", "text/html", "Real"},
	}
	for _, c := range cases {
		if got := Title([]byte(c.body), c.ct); got != c.want {
			t.Errorf("Title(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func TestTitleAfterLargeInlineHead(t *testing.T) {
	// spring.io: the title follows ~333 KiB of inline styles.
	body := "<html><head><style>" + strings.Repeat("a{b:c}", 340<<10/6) + "</style><title data-x=\"1\">Spring | Home</title>"
	if got := Title([]byte(body), "text/html"); got != "Spring | Home" {
		t.Fatalf("got %q", got)
	}
}

func TestTitleIsBounded(t *testing.T) {
	body := "<html><head>" + strings.Repeat("<meta x=y>", TitleScanLimit/10+10) + "<title>late</title>"
	if got := Title([]byte(body), "text/html"); got != "" {
		t.Fatalf("title beyond scan limit should not be found, got %q", got)
	}
	long := "<title>" + strings.Repeat("a", 10*MaxTitleLen) + "</title>"
	if got := Title([]byte(long), "text/html"); len(got) != MaxTitleLen {
		t.Fatalf("title not capped: %d", len(got))
	}
}

func TestIsTitleCandidate(t *testing.T) {
	if !IsTitleCandidate("text/html", nil) || !IsTitleCandidate("application/xhtml+xml", nil) {
		t.Fatal("html types must be candidates")
	}
	if IsTitleCandidate("image/png", []byte("<title>x</title>")) {
		t.Fatal("images are not candidates")
	}
	if !IsTitleCandidate("", []byte("<!doctype html><HTML>")) {
		t.Fatal("missing content type should be sniffed")
	}
}

func TestMurmur3Vectors(t *testing.T) {
	// Reference values from the Python mmh3 package (signed 32-bit, seed 0).
	cases := map[string]int32{"": 0, "hello": 613153351, "foo": -156908512, "The quick brown fox jumps over the lazy dog": 776992547}
	for in, want := range cases {
		if got := int32(Murmur3([]byte(in), 0)); got != want {
			t.Errorf("mmh3(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestFaviconHashWrapsBase64(t *testing.T) {
	// 100 bytes -> 136 base64 chars -> two lines (76 + 60), each "\n"-terminated.
	data := []byte(strings.Repeat("x", 100))
	h := FaviconHash(data)
	if h == "" || h == Hash("mmh3", data) {
		t.Fatalf("favicon hash must hash the wrapped base64, got %q", h)
	}
}

func TestCounts(t *testing.T) {
	// split on single spaces only, so "c\nd" is one word.
	w, l := Counts([]byte("a b c\nd e\n"))
	if w != 4 || l != 2 {
		t.Fatalf("got words=%d lines=%d", w, l)
	}
	if w, l := Counts(nil); w != 0 || l != 0 {
		t.Fatal("empty body must count zero")
	}
}

func TestFaviconCandidates(t *testing.T) {
	body := `<html><head><base href="/app/"><link rel="Shortcut Icon" href="fav.png">
<link rel="stylesheet" href="x.css"><link rel="icon" href="data:image/png;base64,AAAA"></head><body><link rel="icon" href="late.ico">`
	got := FaviconCandidates([]byte(body), "https://example.com/start")
	want := []string{"https://example.com/app/fav.png", "data:image/png;base64,AAAA", "https://example.com/favicon.ico"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestParseHashList(t *testing.T) {
	if got, err := ParseHashList("MD5, sha256"); err != nil || len(got) != 2 || got[0] != "md5" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := ParseHashList("crc32"); err == nil {
		t.Fatal("unknown algorithm must fail")
	}
	if Hash("sha256", []byte("abc")) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("sha256 mismatch")
	}
}

func TestCSPHosts(t *testing.T) {
	h := http.Header{}
	h.Add("Content-Security-Policy", "default-src 'self'; script-src 'nonce-abc' https://cdn.Example.com/js/ *.static.example.com:443 'sha256-xyz' data: blob:; img-src * https: api.example.org")
	h.Add("Content-Security-Policy-Report-Only", "connect-src wss://ws.example.com [2001:db8::1]:8443 cdn.example.com; report-uri /csp")
	h.Add("Content-Security-Policy", "frame-src https://-bad-.example.com http://no_tld *.")
	got := strings.Join(CSPHosts(h), ",")
	want := "cdn.example.com,static.example.com,api.example.org,ws.example.com,2001:db8::1"
	if got != want {
		t.Fatalf("CSPHosts = %s\nwant      %s", got, want)
	}
	if CSPHosts(http.Header{}) != nil {
		t.Fatal("no CSP header must give nil")
	}
}

// Values from github.com/mfonda/simhash, so -hash simhash output is
// comparable with other tools that use it.
func TestSimhashMatchesLibrary(t *testing.T) {
	for in, want := range map[string]uint64{
		"":            18446744073709551615,
		"Hello World": 9208136714076280015,
		"<html><title>Example Domain</title> visit https://example.com/path now's": 16500614462462455613,
		"Привет мир test_1": 17457167750154052973,
	} {
		if got := Simhash([]byte(in)); got != want {
			t.Errorf("Simhash(%q) = %d, want %d", in, got, want)
		}
	}
	if SimhashDistance(Simhash([]byte("a b c d e f g")), Simhash([]byte("a b c d e f h"))) > 20 {
		t.Error("near-identical texts must be close")
	}
}
