package engine

import (
	"context"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/theLabXHQ/pulse/internal/extract"
	"github.com/theLabXHQ/pulse/internal/lru"
	"github.com/theLabXHQ/pulse/internal/output"
)

// ExcludeRules is -e: targets that are not probed at all
// ("-e cdn" is -ec, handled by Config.ExcludeCDN).
type ExcludeRules struct {
	Private  bool // private, loopback, link-local, CGNAT addresses
	Prefixes []netip.Prefix
	Hosts    []*regexp.Regexp
	Ports    []int
}

func (x ExcludeRules) empty() bool {
	return !x.Private && len(x.Prefixes) == 0 && len(x.Hosts) == 0 && len(x.Ports) == 0
}

func (x ExcludeRules) needsIP() bool { return x.Private || len(x.Prefixes) > 0 }

// ExtractPresets are the -ep patterns. The url and mail presets
// are not anchored (^...$), so they find matches inside a page.
var ExtractPresets = map[string]*regexp.Regexp{
	"url":  regexp.MustCompile(`https?://[a-zA-Z0-9][-a-zA-Z0-9.]{0,252}(?::[0-9]{1,5})?(?:/[-a-zA-Z0-9()@:%_+.~#?&/=]*)?`),
	"ipv4": regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`),
	"mail": regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}`),
}

// excluded reports whether -e rules out the task's host.
func (e *Engine) excluded(ctx context.Context, t *task) bool {
	x := e.cfg.Exclude
	if x.empty() {
		return false
	}
	if p := t.spec.Port; p != 0 && slices.Contains(x.Ports, p) {
		return true
	}
	// A target without a port may be probed on 443 and on 80.
	if t.spec.Port == 0 && slices.Contains(x.Ports, 443) && slices.Contains(x.Ports, 80) {
		return true
	}
	for _, re := range x.Hosts {
		if re.MatchString(t.spec.Host) {
			return true
		}
	}
	if !x.needsIP() || e.client.Proxied() {
		return false
	}
	ips, err := e.client.Resolve(ctx, t.spec.Host)
	if err != nil || len(ips) == 0 {
		return false
	}
	ip := ips[0]
	if x.Private && isPrivate(ip) {
		return true
	}
	for _, p := range x.Prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var privatePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "::/128"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func isPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range privatePrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// extracts applies -er/-ep to the raw header block and body.
func (e *Engine) extracts(headers string, body []byte) map[string][]string {
	if len(e.cfg.Extract) == 0 {
		return nil
	}
	text := headers + "\n" + string(body)
	var out map[string][]string
	for name, re := range e.cfg.Extract {
		var ms []string
		for _, m := range re.FindAllString(text, 1000) {
			if !slices.Contains(ms, m) {
				ms = append(ms, m)
			}
		}
		if len(ms) > 0 {
			if out == nil {
				out = map[string][]string{}
			}
			out[name] = ms
		}
	}
	return out
}

// bodyPreview returns the first n characters of a text body, whitespace
// collapsed (-bp).
func bodyPreview(body []byte, n int) string {
	if n <= 0 || len(body) == 0 {
		return ""
	}
	limit := min(len(body), 4*n+64) // enough bytes for n runes
	s := strings.Join(strings.Fields(strings.ToValidUTF8(string(body[:limit]), "")), " ")
	if r := []rune(s); len(r) > n {
		s = string(r[:n])
	}
	return s
}

// dupFilter drops responses whose body simhash is within 3 bits of an
// earlier response from the same IP (-fd). It remembers a bounded
// number of fingerprints.
type dupFilter struct {
	mu   sync.Mutex
	seen *lru.Cache[uint64, []string] // simhash -> IPs that served it
	keys []uint64                     // insertion order for scanning (bounded)
}

const dupMemory = 4096

func newDupFilter() *dupFilter { return &dupFilter{seen: lru.New[uint64, []string](dupMemory)} }

func (d *dupFilter) duplicate(body []byte, ip string) bool {
	h := extract.Simhash(body)
	d.mu.Lock()
	defer d.mu.Unlock()
	live := d.keys[:0] // drop keys the LRU evicted
	var near uint64
	found := false
	for _, k := range d.keys {
		if _, ok := d.seen.Get(k); !ok {
			continue
		}
		live = append(live, k)
		if !found && extract.SimhashDistance(k, h) <= 3 {
			near, found = k, true
		}
	}
	d.keys = live
	if found {
		ips, _ := d.seen.Get(near)
		if ip == "" || slices.Contains(ips, ip) {
			return true
		}
		d.seen.Set(near, append(ips, ip))
		return false
	}
	d.seen.Set(h, []string{ip})
	d.keys = append(d.keys, h)
	return false
}

// errorPage is -fep: status >= 400, or a 200-class page whose title says
// it is an error (soft 404). A transparent heuristic, no model.
func errorPage(r *output.Result) bool {
	if r.StatusCode >= 400 {
		return true
	}
	t := strings.ToLower(r.Title)
	for _, w := range []string{"404", "not found", "page not found", "error 4", "error 5", "does not exist", "no longer available"} {
		if strings.Contains(t, w) {
			return true
		}
	}
	return false
}
