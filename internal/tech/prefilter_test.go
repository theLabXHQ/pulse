package tech

import (
	"fmt"
	"math/rand"
	"regexp/syntax"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode"

	upstream "github.com/projectdiscovery/wappalyzergo"
)

func TestRequired(t *testing.T) {
	for expr, want := range map[string]string{
		`(?i)wp-content/themes/`:                            "wp-content/themes/",
		`(?i)<link[^>]+jquery\.min\.js`:                     "jquery.min.js",
		`(?i)(?:foo|bar)baz`:                                "barbaz|foobaz",
		`(?i)(?:foo|bar)[a-z]baz`:                           "baz", // same min length: the smaller set wins
		`(?i)(?:foo|ba)`:                                    "",
		`(?i)(?:<!--grandnode |powered by)\d`:               "<!--grandnode |powered by",
		`(?i)<div class="[^"]*aem-grid`:                     "aem-grid", // rare beats long but common
		`(?i)href=["']wss?://`:                              "href=\"ws://|href=\"wss://|href='ws://|href='wss://",
		`(?i)[a-z]{3}sk`:                                    "", // [a-z] under (?i) includes U+212A
		`(?i)ab`:                                            "", // too short
		`(?i)x{0,250}drupal`:                                "drupal",
		`(?i)(drupal){1,250}`:                               "drupal",
		`(?i)(drupal)?`:                                     "",
		`(?i)Ünicode-ext`:                                   "nicode-ext",
		`(?i)powered by ((?:\d+\.)+\d+) cms`:                "powered by ",
		`(?i)<[^>]+class="[^"]*(?:uk-container|uk-section)`: "uk-container|uk-section",
	} {
		re, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		got := required(re)
		sort.Strings(got)
		if g := strings.Join(got, "|"); g != want {
			t.Errorf("required(%q) = %q, want %q", expr, g, want)
		}
	}
}

func TestLiteralSet(t *testing.T) {
	s := newLiteralSet([]string{"he", "she", "his", "hers", "xyz"})
	found := s.find([]byte("ushers"))
	got := map[string]bool{}
	for id, ok := range found {
		if ok {
			got[s.lits[id]] = true
		}
	}
	if len(got) != 3 || !got["he"] || !got["she"] || !got["hers"] {
		t.Fatalf("got %v", got)
	}
}

// sample generates a string matched by re. Literal case is randomized to
// exercise case folding; enc optionally encodes letters as HTML entities;
// longS spells every literal 's' as U+017F, which (?i) also matches.
func sample(re *syntax.Regexp, rng *rand.Rand, enc, longS bool) string {
	var b strings.Builder
	var gen func(re *syntax.Regexp)
	gen = func(re *syntax.Regexp) {
		switch re.Op {
		case syntax.OpLiteral:
			for _, r := range re.Rune {
				if longS && re.Flags&syntax.FoldCase != 0 && (r == 's' || r == 'S') {
					b.WriteRune('\u017f')
					continue
				}
				if re.Flags&syntax.FoldCase != 0 && rng.Intn(2) == 0 {
					r = unicode.SimpleFold(r)
					if r > unicode.MaxASCII && rng.Intn(4) != 0 {
						r = unicode.SimpleFold(r) // mostly stay ASCII
					}
				}
				if enc && r < 0x80 && unicode.IsLetter(r) && rng.Intn(3) == 0 {
					fmt.Fprintf(&b, "&#x%X;", unicode.ToUpper(r))
					continue
				}
				b.WriteRune(r)
			}
		case syntax.OpCharClass:
			if len(re.Rune) > 0 {
				lo, hi := re.Rune[0], re.Rune[1]
				r := lo + rune(rng.Intn(int(min(hi-lo, 25))+1))
				if r == '<' || r == '>' || r == '"' || r == '&' || r < ' ' {
					r = lo
				}
				b.WriteRune(r)
			}
		case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
			b.WriteByte('x')
		case syntax.OpCapture:
			gen(re.Sub[0])
		case syntax.OpPlus:
			gen(re.Sub[0])
		case syntax.OpRepeat:
			for i := 0; i < re.Min; i++ {
				gen(re.Sub[0])
			}
		case syntax.OpConcat:
			for _, s := range re.Sub {
				gen(s)
			}
		case syntax.OpAlternate:
			gen(re.Sub[rng.Intn(len(re.Sub))])
		}
	}
	gen(re)
	return b.String()
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestPrefilterMatchesUpstream generates a positive sample for every html and
// script-src pattern and checks that the prefiltered matcher reports exactly
// what upstream wappalyzergo reports.
func TestPrefilterMatchesUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("slow differential test")
	}
	up, err := upstream.New()
	if err != nil {
		t.Fatal(err)
	}
	ours, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	var pages []string
	for _, fp := range ours.fingerprints.Apps {
		for _, p := range fp.html {
			if p.expr == "" {
				pages = append(pages, "<html><body>x</body></html>") // matches anything
				continue
			}
			re, err := syntax.Parse(p.expr, syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			pages = append(pages, "<html><body><p>"+sample(re, rng, false, false)+"</p></body></html>")
			if strings.Contains(strings.Join(p.literals, ""), "s") {
				pages = append(pages, "<html><body><p>"+sample(re, rng, false, true)+"</p></body></html>")
			}
		}
		for _, p := range fp.scriptSrc {
			if p.expr == "" {
				pages = append(pages, `<html><script src="/x.js"></script></html>`) // matches anything
				continue
			}
			re, err := syntax.Parse(p.expr, syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			pages = append(pages, `<html><script src="`+sample(re, rng, true, false)+`"></script></html>`)
		}
	}
	type headerCase struct {
		h    map[string][]string
		body string
	}
	var hcases []headerCase
	gen := func(p *ParsedPattern) string {
		if p == nil || p.expr == "" {
			return "x"
		}
		re, err := syntax.Parse(p.expr, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		return sample(re, rng, false, false)
	}
	for _, fp := range ours.fingerprints.Apps {
		for k, p := range fp.headers {
			hcases = append(hcases, headerCase{h: map[string][]string{k: {gen(p)}, "X-Pulse-Filler": {"1"}}})
		}
		for k, p := range fp.cookies {
			hcases = append(hcases, headerCase{h: map[string][]string{"Set-Cookie": {k + "=" + gen(p) + "; path=/"}}})
		}
		for k, ps := range fp.meta {
			for _, p := range ps {
				hcases = append(hcases, headerCase{body: `<html><head><meta name="` + k + `" content="` + gen(p) + `"></head></html>`})
			}
		}
	}
	// Bodies that defeat the filter's assumptions.
	pages = append(pages,
		"<html>ſome wordpreſſ wp-content</html>",
		"<html>Kelvin wp-content/themes/</html>",
		"",
	)
	var mismatches, nonEmpty int
	for _, page := range pages {
		want := sortedKeys(up.Fingerprint(nil, []byte(page)))
		got := sortedKeys(ours.Fingerprint(nil, []byte(page)))
		if len(want) > 0 {
			nonEmpty++
		}
		if strings.Join(want, ",") != strings.Join(got, ",") {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("page %.120q\n upstream: %v\n     ours: %v", page, want, got)
			}
		}
	}
	for _, c := range hcases {
		want := sortedKeys(up.Fingerprint(c.h, []byte(c.body)))
		got := sortedKeys(ours.Fingerprint(c.h, []byte(c.body)))
		if len(want) > 0 {
			nonEmpty++
		}
		if strings.Join(want, ",") != strings.Join(got, ",") {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("headers %v body %.80q\n upstream: %v\n     ours: %v", c.h, c.body, want, got)
			}
		}
	}
	pages = append(pages, make([]string, len(hcases))...) // for the totals below
	if mismatches > 0 {
		t.Fatalf("%d/%d cases differ", mismatches, len(pages))
	}
	// Guard against a vacuous test: most generated samples must hit.
	if nonEmpty < len(pages)/2 {
		t.Fatalf("only %d/%d samples matched anything; generator is broken", nonEmpty, len(pages))
	}
	t.Logf("%d cases, %d with detections, identical results", len(pages), nonEmpty)
}

func benchPage(n int) []byte {
	var b strings.Builder
	b.WriteString(`<html><head><title>Shop</title><meta name="generator" content="WordPress 6.4"><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script></head><body>`)
	for b.Len() < n {
		b.WriteString(`<div class="product"><a href="/item">Lorem ipsum dolor sit amet, consectetur adipiscing elit</a><span>$19.99</span></div>`)
	}
	b.WriteString(`</body></html>`)
	return []byte(b.String())
}

func BenchmarkFingerprint(b *testing.B) {
	up, _ := upstream.New()
	ours, _ := New()
	h := map[string][]string{"Server": {"nginx/1.25"}, "X-Powered-By": {"PHP/8.2"}}
	for _, size := range []int{2 << 10, 64 << 10, 1 << 20} {
		page := benchPage(size)
		b.Run(fmt.Sprintf("upstream/%dKiB", size>>10), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				up.Fingerprint(h, page)
			}
		})
		b.Run(fmt.Sprintf("pulse/%dKiB", size>>10), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ours.Fingerprint(h, page)
			}
		})
	}
}

func TestLitIndexCandidates(t *testing.T) {
	mk := func(app, expr string) patRef {
		p, err := ParsePattern(expr)
		if err != nil {
			t.Fatal(err)
		}
		return patRef{app: app, p: p}
	}
	li := newLitIndex([]patRef{
		mk("a", `drupal`),
		mk("b", `(?:joomla|mambo)`),
		mk("c", `\d+`), // no literal: always a candidate
		mk("d", `drupal\.js`),
	})
	names := func(refs []patRef) string {
		var s []string
		for _, r := range refs {
			s = append(s, r.app)
		}
		return strings.Join(s, ",")
	}
	for in, want := range map[string]string{
		"powered by Drupal": "a,c",
		"/misc/DRUPAL.JS":   "a,c,d",
		"mambo server":      "b,c",
		"nothing":           "c",
		"druſal mambo":      "a,b,c,d", // long s: no filtering
	} {
		if got := names(li.candidates(in)); got != want {
			t.Errorf("candidates(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestConcurrentLazyCompile runs detection from many goroutines; with -race it
// checks that compiling patterns on first use is safe.
func TestConcurrentLazyCompile(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	page := benchPage(8 << 10)
	h := map[string][]string{"Server": {"nginx/1.25"}, "Set-Cookie": {"PHPSESSID=1; path=/"}}
	want := strings.Join(sortedKeys(w.Fingerprint(h, page)), ",")
	w, _ = New() // fresh: nothing compiled yet
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := strings.Join(sortedKeys(w.Fingerprint(h, page)), ","); got != want {
				t.Errorf("got %s, want %s", got, want)
			}
		}()
	}
	wg.Wait()
}
