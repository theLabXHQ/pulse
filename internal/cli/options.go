// Package cli wires flags to the engine: parsing, validation, signals,
// resume, statistics and the final summary.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/http/httpguts"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/theLabXHQ/pulse/internal/cdn"
	"github.com/theLabXHQ/pulse/internal/dsl"
	"github.com/theLabXHQ/pulse/internal/engine"
	"github.com/theLabXHQ/pulse/internal/extract"
	"github.com/theLabXHQ/pulse/internal/input"
	"github.com/theLabXHQ/pulse/internal/match"
	"github.com/theLabXHQ/pulse/internal/output"
	"github.com/theLabXHQ/pulse/internal/probe"
	"github.com/theLabXHQ/pulse/internal/target"
)

// Options holds every CLI setting.
type Options struct {
	Targets, Lists []string
	Resume         string
	InputMode      string
	RawRequest     string // -request file
	Unsafe         bool

	Fields output.TextFields
	Hash   string

	MatchCode, FilterCode, MatchLength, FilterLength   string
	MatchLines, FilterLines, MatchWords, FilterWords   string
	MatchString, FilterString, MatchRegex, FilterRegex []string
	MatchFavicon, FilterFavicon                        []string
	MatchCDN, FilterCDN                                []string
	MatchDSL, FilterDSL                                []string
	ExcludeCDN                                         bool
	TLSProbe, CSPProbe                                 bool
	DiscoverScope                                      string
	DiscoverDepth, DiscoverMax                         int
	ASNDB                                              string
	Adaptive                                           bool
	NoDNSFallback                                      bool
	NoStdin, RandomAgent, LeaveDefaultPorts            bool
	FilterDuplicates, FilterErrorPage                  bool
	BodyPreview                                        int
	Delay                                              time.Duration
	ExtractRegex, ExtractPreset, Exclude               []string
	MatchRT, FilterRT                                  string
	compat                                             bool // accepted flags that change nothing in Pulse

	Ports, Paths, Methods, Body string
	Headers                     []string
	Proxy, SNI                  string
	Resolvers                   []string
	FollowRedirects, FollowHost bool
	MaxRedirects                int
	NoFallback, HTTP2, HTTP1    bool
	Impersonate                 bool
	NoDedupe                    bool
	Deny                        []string
	ExcludePrivate              bool
	KeepAlive                   string

	Threads, HostConcurrency int
	RateLimit, RateLimitHost float64
	RateLimitMinute          int
	MaxHostErrors            int
	Timeout                  time.Duration
	Retries                  int
	MaxBody                  int64

	Output, StoreDir string
	JSON, CSV        bool
	IncludeHeaders   bool
	IncludeBody      bool
	StoreResponse    bool
	NoColor, Silent  bool
	Verbose, Stats   bool
	StatsInterval    time.Duration
	Version          bool
	EnrichThreads    int
	CPUProfile       string
	MemProfile       string

	// derived
	portSpecs []target.PortSpec
	pathList  []string
	methods   []string
	header    http.Header
	rules     *match.Rules
	raw       []byte // -unsafe: request bytes sent as is
	extract   map[string]*regexp.Regexp
	exclude   engine.ExcludeRules
	hashes    []string
	deny      []netip.Prefix
}

func defaultOptions() *Options {
	return &Options{
		MaxRedirects:    10,
		KeepAlive:       "auto",
		Threads:         50,
		HostConcurrency: 8,
		RateLimit:       150,
		MaxHostErrors:   30,
		Timeout:         10 * time.Second,
		MaxBody:         1 << 20,
		StoreDir:        "output",
		StatsInterval:   5 * time.Second,
		DiscoverScope:   "domain",
		HTTP2:           true, // browsers do; a "Chrome" speaking HTTP/1.1 is a bot signal
		DiscoverDepth:   1,
		DiscoverMax:     10000,
	}
}

// parse parses args into Options. It returns flag.ErrHelp for -h.
func parse(args []string, stderr io.Writer) (*Options, error) {
	o := defaultOptions()
	fs := flag.NewFlagSet("pulse", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := &registry{fs: fs}

	in := r.group("Input")
	r.varFlag(in, listFlag{&o.Targets, true}, "string", "target(s) to probe (repeatable, comma separated)", "", "u", "target")
	r.varFlag(in, listFlag{&o.Lists, false}, "file", "file with targets, one per line; '-' for stdin (repeatable)", "", "l", "list")
	r.stringVar(in, &o.Resume, "resume file: continue from it if it exists, save progress to it", "resume")
	r.stringVar(in, &o.InputMode, "format of -l files and stdin: burp (Burp Suite XML export)", "im", "input-mode")
	r.stringVar(in, &o.RawRequest, "file with a raw HTTP request (method, path, headers, body) to send to every target; its Host is the target if none is given", "rr", "request")
	r.boolVar(in, &o.Unsafe, "with -request: send the file's bytes unchanged (no Go normalization, no redirects)", "unsafe")

	pr := r.group("Probes (text output fields)")
	r.boolVar(pr, &o.Fields.StatusCode, "display status code (redirect chain when following)", "sc", "status-code")
	r.boolVar(pr, &o.Fields.ContentLength, "display content length", "cl", "content-length")
	r.boolVar(pr, &o.Fields.ContentType, "display content type", "ct", "content-type")
	r.boolVar(pr, &o.Fields.Location, "display redirect location / final URL", "location")
	r.boolVar(pr, &o.Fields.Title, "display page title", "title")
	r.boolVar(pr, &o.Fields.WebServer, "display Server header", "server", "web-server")
	r.boolVar(pr, &o.Fields.Tech, "detect technologies (Wappalyzer dataset, enrichment stage)", "td", "tech-detect")
	r.boolVar(pr, &o.Fields.IP, "display connected IP", "ip")
	r.boolVar(pr, &o.Fields.CDN, "display CDN/WAF/cloud provider of the IP (offline ranges; always in JSON/CSV)", "cdn")
	r.boolVar(pr, &o.Fields.ASN, "display the AS of the IP (Team Cymru DNS, or offline with -asn-db)", "asn")
	r.stringVar(pr, &o.ASNDB, "offline AS lookups from an iptoasn.com TSV file (.tsv or .tsv.gz); implies -asn", "asn-db")
	r.boolVar(pr, &o.Fields.ResponseTime, "display total probe time", "rt", "response-time")
	r.boolVar(pr, &o.Fields.Favicon, "fetch favicon and display Shodan mmh3 hash (enrichment stage)", "favicon")
	r.stringVar(pr, &o.Hash, "display body hash: md5,sha1,sha256,mmh3", "hash")
	r.boolVar(pr, &o.Fields.Lines, "display body line count", "lc", "line-count")
	r.boolVar(pr, &o.Fields.Words, "display body word count", "wc", "word-count")
	r.boolVar(pr, &o.Fields.Method, "display request method", "method")
	r.boolVar(pr, &o.Fields.HTTPVersion, "display negotiated HTTP version", "hv", "http-version")
	r.boolVar(pr, &o.Fields.TLS, "display TLS version", "tls")
	r.boolVar(pr, &o.Fields.Probe, "also output failed probes with their error class", "probe")
	r.varFlag(pr, optIntFlag{&o.BodyPreview, 100}, "", "show the first N characters of the body (-bp or -bp=N, default 100)", "", "bp", "body-preview")
	r.boolVar(pr, &o.Fields.CNAME, "display the host's CNAME chain", "cname")
	r.varFlag(pr, listFlag{&o.ExtractRegex, false}, "regex", "extract body/header matches of a regex (repeatable)", "", "er", "extract-regex")
	r.varFlag(pr, listFlag{&o.ExtractPreset, true}, "list", "extract with presets: url, ipv4, mail", "", "ep", "extract-preset")
	r.boolVar(pr, &o.Fields.Pipeline, "detect HTTP/1.1 pipelining support (enrichment, one extra connection)", "pipeline")
	r.boolVar(pr, &o.Fields.VHost, "detect virtual hosts: does a random Host header get another page? (enrichment, 1-2 extra requests)", "vhost")

	m := r.group("Matchers")
	r.stringVar(m, &o.MatchCode, "match status codes, e.g. 200,301-303", "mc", "match-code")
	r.stringVar(m, &o.MatchLength, "match content length", "ml", "match-length")
	r.stringVar(m, &o.MatchLines, "match body line count", "mlc", "match-line-count")
	r.stringVar(m, &o.MatchWords, "match body word count", "mwc", "match-word-count")
	r.varFlag(m, listFlag{&o.MatchString, false}, "string", "match string in headers or body, case-insensitive (repeatable)", "", "ms", "match-string")
	r.varFlag(m, listFlag{&o.MatchRegex, false}, "regex", "match regex in headers or body (repeatable)", "", "mr", "match-regex")
	r.varFlag(m, listFlag{&o.MatchFavicon, true}, "string", "match favicon mmh3 hash (implies -favicon)", "", "mfc", "match-favicon")
	r.stringVar(m, &o.MatchRT, "match response time in seconds, e.g. '< 1' or '>= 0.5'", "mrt", "match-response-time")
	r.varFlag(m, listFlag{&o.MatchDSL, false}, "expr", `match DSL expression, e.g. 'status_code == 200 && contains(body, "admin")' (repeatable)`, "", "mdc", "match-condition")
	r.varFlag(m, listFlag{&o.MatchCDN, true}, "string", "match CDN provider or kind (cdn, waf, cloud), e.g. cloudflare,waf", "", "mcdn", "match-cdn")

	f := r.group("Filters")
	r.stringVar(f, &o.FilterCode, "filter status codes", "fc", "filter-code")
	r.stringVar(f, &o.FilterLength, "filter content length", "fl", "filter-length")
	r.stringVar(f, &o.FilterLines, "filter body line count", "flc", "filter-line-count")
	r.stringVar(f, &o.FilterWords, "filter body word count", "fwc", "filter-word-count")
	r.varFlag(f, listFlag{&o.FilterString, false}, "string", "filter string in headers or body, case-insensitive (repeatable)", "", "fs", "filter-string")
	r.varFlag(f, listFlag{&o.FilterRegex, false}, "regex", "filter regex in headers or body (repeatable)", "", "fe", "filter-regex")
	r.varFlag(f, listFlag{&o.FilterFavicon, true}, "string", "filter favicon mmh3 hash (implies -favicon)", "", "ffc", "filter-favicon")
	r.stringVar(f, &o.FilterRT, "filter response time in seconds, e.g. '> 3'", "frt", "filter-response-time")
	r.boolVar(f, &o.FilterDuplicates, "drop near-duplicate responses from the same IP (simhash)", "fd", "filter-duplicates")
	r.boolVar(f, &o.FilterErrorPage, "drop error pages: status >= 400 and 200 pages titled like 404/not found", "fep", "filter-error-page")
	r.varFlag(f, listFlag{&o.FilterDSL, false}, "expr", "filter DSL expression (repeatable)", "", "fdc", "filter-condition")
	r.varFlag(f, listFlag{&o.FilterCDN, true}, "string", "filter CDN provider or kind (cdn, waf, cloud)", "", "fcdn", "filter-cdn")

	c := r.group("Request")
	r.stringVar(c, &o.Ports, "ports to probe, e.g. 80,443,8000-8010,http:8080,https:8443", "p", "ports")
	r.boolVar(c, &o.ExcludeCDN, "probe only ports 80/443 on CDN/WAF addresses (not cloud)", "ec", "exclude-cdn")
	r.stringVar(c, &o.Paths, "path(s) to probe: comma list or file", "path")
	r.stringVar(c, &o.Methods, "request method(s), comma separated", "x", "method-list")
	r.stringVar(c, &o.Body, "request body", "body")
	r.varFlag(c, listFlag{&o.Headers, false}, "header", "custom header 'Name: value' (repeatable)", "", "H", "header")
	r.stringVar(c, &o.Proxy, "proxy URL (http, https, socks5)", "proxy", "http-proxy")
	r.boolVar(c, &o.FollowRedirects, "follow redirects", "fr", "follow-redirects")
	r.boolVar(c, &o.FollowHost, "follow redirects on the same host only", "fhr", "follow-host-redirects")
	r.intVar(c, &o.MaxRedirects, "max redirects to follow", "maxr", "max-redirects")
	r.boolVar(c, &o.NoFallback, "probe both HTTPS and HTTP and report both", "nf", "no-fallback")
	r.boolVar(c, &o.HTTP2, "offer HTTP/2 via ALPN (default; reported in http_version)", "http2")
	r.boolVar(c, &o.HTTP1, "speak only HTTP/1.1 (no ALPN h2)", "http1")
	r.varFlag(c, impersonateFlag{&o.Impersonate}, "", "retry pages that look blocked by a bot manager with Chrome's TLS fingerprint (no -proxy)", "", "tlsi", "tls-impersonate")
	r.stringVar(c, &o.SNI, "custom TLS SNI name", "sni", "sni-name")
	r.varFlag(c, listFlag{&o.Resolvers, true}, "list", "DNS resolvers ip[:port] (comma list or file)", "", "r", "resolvers")
	r.boolVar(c, &o.NoDNSFallback, "without -r, never switch to 1.1.1.1/8.8.8.8 when the system resolver stops answering", "no-dns-fallback")
	r.varFlag(c, listFlag{&o.Deny, true}, "cidr", "never connect to these IPs/CIDRs (checked after DNS)", "", "deny")
	r.boolVar(c, &o.ExcludePrivate, "deny private, loopback, link-local, CGNAT and unspecified addresses (checked after DNS)", "exclude-private")
	r.varFlag(c, listFlag{&o.Exclude, true}, "list", "exclude hosts: cdn, private-ips, an IP, a CIDR or a host regex (comma list)", "", "e", "exclude")
	r.durationVar(c, &o.Delay, "pause before each request (e.g. 200ms)", "delay")
	r.boolVar(c, &o.RandomAgent, "a random browser User-Agent per request (default: one fixed Chrome UA)", "random-agent")
	r.boolVar(c, &o.LeaveDefaultPorts, "keep :80/:443 in URLs and the Host header", "ldp", "leave-default-ports")
	r.boolVar(c, &o.NoStdin, "never read targets from stdin", "no-stdin")
	r.boolVar(c, &o.NoDedupe, "do not deduplicate input targets", "sd", "skip-dedupe")
	r.stringVar(c, &o.KeepAlive, "connection reuse: auto|on|off (auto = on when >1 request per host)", "keep-alive")

	dg := r.group("Discovery")
	r.boolVar(dg, &o.TLSProbe, "also probe hostnames from TLS certificates (SAN, CN)", "tls-probe")
	r.boolVar(dg, &o.CSPProbe, "also probe hostnames from Content-Security-Policy headers", "csp-probe")
	r.stringVar(dg, &o.DiscoverScope, "follow discovered names: domain (same registrable domain as the source) or any", "discover-scope")
	r.intVar(dg, &o.DiscoverDepth, "discovery hops from input targets", "discover-depth")
	r.intVar(dg, &o.DiscoverMax, "max discovered names in total", "discover-max")

	rl := r.group("Rate limit and concurrency")
	r.intVar(rl, &o.Threads, "concurrent probes", "t", "threads", "c")
	r.intVar(rl, &o.HostConcurrency, "concurrent probes per host (0 = unlimited)", "ch", "concurrency-host")
	r.boolVar(rl, &o.Adaptive, "slow down per host on 429/503/timeouts (Retry-After) and globally when the local network congests; recover on success", "adaptive")
	r.floatVar(rl, &o.RateLimit, "max requests per second, all hosts (0 = unlimited)", "rl", "rate-limit")
	r.intVar(rl, &o.RateLimitMinute, "max requests per minute (overrides -rl)", "rlm", "rate-limit-minute")
	r.floatVar(rl, &o.RateLimitHost, "max requests per second per host (0 = unlimited)", "rlh", "rate-limit-host")
	r.intVar(rl, &o.MaxHostErrors, "skip host:port after N consecutive connection failures (0 = off)", "maxhr", "max-host-error")
	r.intVar(rl, &o.EnrichThreads, "enrichment workers for -favicon/-td (0 = auto)", "et", "enrich-threads")

	op := r.group("Timeouts and limits")
	r.varFlag(op, secondsFlag{&o.Timeout}, "duration", "timeout per attempt incl. redirects and body (seconds or Go duration)", o.Timeout.String(), "timeout")
	r.intVar(op, &o.Retries, "retries after transient network errors", "retries")
	r.varFlag(op, sizeFlag{&o.MaxBody}, "size", "max (decoded) body bytes to read per response", "1m", "rstr", "response-size-to-read", "max-body")

	out := r.group("Output")
	r.stringVar(out, &o.Output, "also write results to this file", "o", "output")
	r.boolVar(out, &o.JSON, "JSON Lines output (schema pulse.v1)", "j", "json")
	r.boolVar(out, &o.CSV, "CSV output", "csv")
	r.boolVar(out, &o.IncludeHeaders, "include response headers in JSON", "irh", "include-response-header")
	r.boolVar(out, &o.IncludeBody, "include response headers and body in JSON", "irr", "include-response")
	r.boolVar(out, &o.StoreResponse, "store responses to -srd directory", "sr", "store-response")
	r.stringVar(out, &o.StoreDir, "directory for stored responses", "srd", "store-response-dir")
	r.boolVar(out, &o.NoColor, "disable colors", "nc", "no-color")
	r.boolVar(out, &o.Silent, "only print results (no banner/summary)", "silent")
	r.boolVar(out, &o.Verbose, "log every failed probe with its error class", "v", "verbose")
	r.boolVar(out, &o.Stats, "print progress statistics to stderr", "stats")
	r.varFlag(out, secondsFlag{&o.StatsInterval}, "duration", "statistics interval", "5s", "si", "stats-interval")
	r.boolVar(out, &o.Version, "print version and exit", "version")

	dbg := r.group("Diagnostics")
	r.stringVar(dbg, &o.CPUProfile, "write a Go CPU profile to this file", "cpuprofile")
	r.stringVar(dbg, &o.MemProfile, "write a Go heap profile to this file at exit", "memprofile")

	// Common flags whose effect is already Pulse's default behaviour.
	r.compatVar(&o.compat, "duc", "disable-update-check", "s", "stream", "tls-grab", "include-chain",
		"nfs", "no-fallback-scheme")

	// The flag package calls Usage on every parse error; help is printed
	// once, below, and only for -h (errors get a one-line message).
	fs.Usage = func() {}
	var fullHelp bool
	fs.BoolVar(&fullHelp, "hh", false, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, &helpRequest{r: r}
		}
		return nil, err
	}
	if fullHelp {
		return nil, &helpRequest{full: true, r: r}
	}
	// Bare arguments are targets for convenience, but only ones that look
	// like targets: the flag package stops at the first non-flag, so a
	// value given to a Pulse switch that takes none (such as
	// "-tlsi chrome") would otherwise turn every later flag into a "target".
	for _, a := range fs.Args() {
		if err := bareTarget(a); err != nil {
			return nil, err
		}
		o.Targets = append(o.Targets, a)
	}
	return o, nil
}

var privateRanges = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "::/128",
}

// validate checks and derives settings.
func (o *Options) validate() error {
	var err error
	if o.Threads < 1 {
		return errors.New("-t must be >= 1")
	}
	if o.Timeout <= 0 {
		return errors.New("-timeout must be > 0")
	}
	for _, n := range []struct {
		name string
		v    float64
	}{
		{"-rl", o.RateLimit}, {"-rlm", float64(o.RateLimitMinute)}, {"-rlh", o.RateLimitHost},
		{"-retries", float64(o.Retries)}, {"-ch", float64(o.HostConcurrency)}, {"-maxhr", float64(o.MaxHostErrors)},
		{"-maxr", float64(o.MaxRedirects)}, {"-et", float64(o.EnrichThreads)},
	} {
		if n.v < 0 {
			return fmt.Errorf("%s must be >= 0", n.name)
		}
	}
	if o.MaxRedirects == 0 { // -maxr 0: follow none (the client's 0 means "default")
		o.FollowRedirects, o.FollowHost = false, false
	}
	if o.MaxBody == 0 {
		return errors.New("-rstr must be > 0")
	}
	if o.StoreResponse {
		if err := os.MkdirAll(o.StoreDir, 0o755); err != nil {
			return fmt.Errorf("-srd: %w", err)
		}
	}
	if o.StatsInterval <= 0 {
		return errors.New("-si must be > 0")
	}
	if o.MaxBody < 0 {
		return errors.New("-rstr must be >= 0")
	}
	if o.JSON && o.CSV {
		return errors.New("-json and -csv are mutually exclusive")
	}
	rawPath, err := o.applyRawRequest()
	if err != nil {
		return err
	}
	if o.Ports != "" {
		if o.portSpecs, err = target.ParsePorts(o.Ports); err != nil {
			return fmt.Errorf("-p: %w", err)
		}
	}
	if o.Paths != "" {
		if o.pathList, err = loadList(o.Paths); err != nil {
			return fmt.Errorf("-path: %w", err)
		}
	}
	if rawPath != "" && o.Paths == "" {
		o.pathList = []string{rawPath} // as is: a query may contain commas
	}
	if strings.EqualFold(strings.TrimSpace(o.Methods), "all") { // every method
		o.Methods = "GET,HEAD,POST,PUT,PATCH,DELETE,CONNECT,OPTIONS,TRACE"
	}
	for _, m := range strings.Split(o.Methods, ",") {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			if !httpguts.ValidHeaderFieldName(m) { // a method is an HTTP token
				return fmt.Errorf("-x: invalid method %q", m)
			}
			o.methods = append(o.methods, m)
		}
	}
	if len(o.methods) > 1 {
		o.Fields.Method = true
	}
	o.header = http.Header{}
	for _, h := range o.Headers {
		k, v, ok := strings.Cut(h, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" {
			return fmt.Errorf("-H: expected 'Name: value', got %q", h)
		}
		if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) {
			return fmt.Errorf("-H: invalid header %q (control characters or line breaks?)", h)
		}
		o.header.Add(k, v)
	}
	var res []string
	for _, r := range o.Resolvers {
		if list, lerr := loadList(r); lerr == nil {
			res = append(res, list...)
		}
	}
	o.Resolvers = res
	denies := o.Deny
	if o.ExcludePrivate {
		denies = append(denies, privateRanges...)
	}
	for _, d := range denies {
		p, perr := netip.ParsePrefix(d)
		if perr != nil {
			a, aerr := netip.ParseAddr(d)
			if aerr != nil {
				return fmt.Errorf("-deny: invalid IP/CIDR %q", d)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		o.deny = append(o.deny, p.Masked())
	}
	if o.Hash != "" {
		if o.hashes, err = extract.ParseHashList(o.Hash); err != nil {
			return fmt.Errorf("-hash: %w", err)
		}
		o.Fields.Hash = true
	}
	if o.ASNDB != "" {
		o.Fields.ASN = true
	}
	if o.InputMode != "" && !slices.Contains(input.Formats, o.InputMode) {
		return fmt.Errorf("-im: unsupported format %q (supported: %s)", o.InputMode, strings.Join(input.Formats, ", "))
	}
	if o.HTTP1 {
		o.HTTP2 = false
	}
	if o.Impersonate && o.Proxy != "" {
		return errors.New("-tls-impersonate cannot be combined with -proxy")
	}
	if strings.HasPrefix(o.Resume, "-") {
		return fmt.Errorf("-resume needs a file name, got %q", o.Resume)
	}
	if o.extract, err = compileExtracts(o.ExtractRegex, o.ExtractPreset); err != nil {
		return err
	}
	o.Fields.Extracts = len(o.extract) > 0
	o.Fields.BodyPreview = o.BodyPreview > 0
	if o.exclude, err = o.parseExclude(o.Exclude); err != nil {
		return err
	}
	switch o.DiscoverScope {
	case "domain", "any":
	default:
		return fmt.Errorf("-discover-scope: expected domain or any")
	}
	if o.DiscoverDepth < 1 || o.DiscoverMax < 1 {
		return fmt.Errorf("-discover-depth and -discover-max must be at least 1")
	}
	switch o.KeepAlive {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("-keep-alive: expected auto, on or off")
	}
	if o.RateLimitMinute > 0 {
		o.RateLimit = float64(o.RateLimitMinute) / 60
	}

	rules := &match.Rules{}
	parseSet := func(name, v string, dst *map[int]bool) {
		if err == nil {
			*dst, err = match.ParseInts(v)
			if err != nil {
				err = fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	parseSet("-mc", o.MatchCode, &rules.MatchCodes)
	parseSet("-fc", o.FilterCode, &rules.FilterCodes)
	parseSet("-mlc", o.MatchLines, &rules.MatchLines)
	parseSet("-flc", o.FilterLines, &rules.FilterLines)
	parseSet("-mwc", o.MatchWords, &rules.MatchWords)
	parseSet("-fwc", o.FilterWords, &rules.FilterWords)
	if err != nil {
		return err
	}
	if rules.MatchLengths, err = match.ParseInt64s(o.MatchLength); err != nil {
		return fmt.Errorf("-ml: %w", err)
	}
	if rules.FilterLengths, err = match.ParseInt64s(o.FilterLength); err != nil {
		return fmt.Errorf("-fl: %w", err)
	}
	rules.MatchStrings = match.ParseStrings(o.MatchString)
	rules.FilterStrings = match.ParseStrings(o.FilterString)
	if rules.MatchRegex, err = match.ParseRegexes(o.MatchRegex); err != nil {
		return fmt.Errorf("-mr: %w", err)
	}
	if rules.FilterRegex, err = match.ParseRegexes(o.FilterRegex); err != nil {
		return fmt.Errorf("-fe: %w", err)
	}
	rules.MatchFavicon = match.ParseSet(o.MatchFavicon)
	rules.FilterFavicon = match.ParseSet(o.FilterFavicon)
	if rules.HasFaviconRules() {
		o.Fields.Favicon = true
	}
	if rules.MatchDSL, err = parseDSL("-mdc", o.MatchDSL); err != nil {
		return err
	}
	if rules.FilterDSL, err = parseDSL("-fdc", o.FilterDSL); err != nil {
		return err
	}
	if rules.MatchCDN, err = parseCDN("-mcdn", o.MatchCDN); err != nil {
		return err
	}
	if rules.FilterCDN, err = parseCDN("-fcdn", o.FilterCDN); err != nil {
		return err
	}
	if rules.MatchTime, err = match.ParseTimeCond(o.MatchRT); err != nil {
		return fmt.Errorf("-mrt: %w", err)
	}
	if rules.FilterTime, err = match.ParseTimeCond(o.FilterRT); err != nil {
		return fmt.Errorf("-frt: %w", err)
	}
	o.rules = rules
	if o.IncludeBody {
		o.IncludeHeaders = true
	}
	return nil
}

// loadList returns the lines of a file if v names one, else v split on commas.
func loadList(v string) ([]string, error) {
	if st, err := os.Stat(v); err == nil && !st.IsDir() {
		data, err := os.ReadFile(v)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				out = append(out, l)
			}
		}
		return out, nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// parseCDN validates provider names and kinds against the range database.
func parseCDN(flag string, vals []string) (map[string]bool, error) {
	set := match.ParseSet(vals)
	if len(set) == 0 {
		return nil, nil
	}
	db, err := cdn.Default()
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, n := range append(db.Providers(), cdn.Kinds...) {
		known[n] = true
	}
	lower := make(map[string]bool, len(set))
	for v := range set {
		if v = strings.ToLower(v); v == "" {
			continue
		}
		if !known[v] {
			return nil, fmt.Errorf("%s: unknown provider %q (known: %s, %s)", flag, v,
				strings.Join(cdn.Kinds, ", "), strings.Join(db.Providers(), ", "))
		}
		lower[v] = true
	}
	return lower, nil
}

// parseDSL compiles -mdc/-fdc expressions and rejects unknown variables
// before any probe runs.
func parseDSL(flag string, exprs []string) ([]*dsl.Expr, error) {
	known := map[string]bool{}
	for _, v := range engine.DSLVariables() {
		known[v] = true
	}
	var out []*dsl.Expr
	for _, src := range exprs {
		e, err := dsl.Compile(src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", flag, err)
		}
		for _, v := range e.Variables() {
			if !known[v] {
				return nil, fmt.Errorf("%s: unknown variable %q (known: %s)", flag, v, strings.Join(engine.DSLVariables(), ", "))
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// applyRawRequest folds -request into the options. Explicit -x, -path,
// -body and -H win over the file. It returns the request's path.
func (o *Options) applyRawRequest() (string, error) {
	if o.RawRequest == "" {
		if o.Unsafe {
			return "", errors.New("-unsafe needs -request")
		}
		return "", nil
	}
	data, err := os.ReadFile(o.RawRequest)
	if err != nil {
		return "", fmt.Errorf("-request: %w", err)
	}
	rr, err := probe.ParseRawRequest(data)
	if err != nil {
		return "", fmt.Errorf("-request: %w", err)
	}
	if o.Methods == "" {
		o.Methods = rr.Method
	}
	if o.Body == "" {
		o.Body = rr.Body
	}
	for k, vs := range rr.Header {
		switch k {
		case "Content-Length", "Transfer-Encoding", "Connection": // computed per request
			continue
		}
		for _, v := range vs {
			o.Headers = append(o.Headers, k+": "+v)
		}
	}
	if len(o.Targets) == 0 && len(o.Lists) == 0 {
		if rr.Host == "" {
			return "", errors.New("-request: no Host header and no -u/-l target")
		}
		t := rr.Host
		if u, err := url.Parse(rr.URI); err == nil && u.IsAbs() {
			t = u.Scheme + "://" + u.Host
		}
		o.Targets = []string{t}
	}
	if o.Unsafe {
		if o.Proxy != "" {
			return "", errors.New("-unsafe cannot go through -proxy")
		}
		o.raw = data
	}
	return rr.Path(), nil
}

// bareTarget rejects stray arguments that are not plausible targets.
func bareTarget(a string) error {
	switch {
	case strings.HasPrefix(a, "-"):
		return fmt.Errorf("flag %s after a target or a stray value: put flags before bare targets, or use -u", a)
	case strings.ContainsAny(a, ".:/") || a == "localhost":
		return nil
	}
	return fmt.Errorf("unexpected argument %q: if it is a flag value, the flag takes none in Pulse or needs =value (e.g. -tlsi=chrome, -bp=200); targets go with -u", a)
}

func compileExtracts(regexes, presets []string) (map[string]*regexp.Regexp, error) {
	out := map[string]*regexp.Regexp{}
	for _, r := range regexes {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("-er: %w", err)
		}
		out[r] = re
	}
	for _, p := range presets {
		re, ok := engine.ExtractPresets[strings.ToLower(p)]
		if !ok {
			return nil, fmt.Errorf("-ep: unknown preset %q (url, ipv4, mail)", p)
		}
		out[strings.ToLower(p)] = re
	}
	return out, nil
}

// parseExclude reads -e values: cdn (= -ec), private-ips, a
// port, an IP, a CIDR, or a host regex.
func (o *Options) parseExclude(vals []string) (engine.ExcludeRules, error) {
	var x engine.ExcludeRules
	for _, v := range vals {
		v = strings.TrimSpace(v)
		switch lv := strings.ToLower(v); {
		case v == "":
		case lv == "cdn":
			o.ExcludeCDN = true // "-e cdn" is -ec
		case isPort(v):
			n, _ := strconv.Atoi(v)
			x.Ports = append(x.Ports, n)
		case lv == "private-ips" || lv == "private":
			x.Private = true
		default:
			if ip, err := netip.ParseAddr(v); err == nil {
				x.Prefixes = append(x.Prefixes, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
			} else if p, err := netip.ParsePrefix(v); err == nil {
				x.Prefixes = append(x.Prefixes, p.Masked())
			} else if re, err := regexp.Compile(v); err == nil {
				x.Hosts = append(x.Hosts, re)
			} else {
				return x, fmt.Errorf("-e: %q is not cdn, private-ips, an IP, a CIDR or a regex", v)
			}
		}
	}
	return x, nil
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}
