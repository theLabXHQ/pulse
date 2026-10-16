// Package engine schedules probes: it turns input lines into tasks, runs them
// on a bounded worker pool with global and per-host limits, applies matchers,
// runs optional enrichment on a separate pool and hands results to output.
//
// Memory is bounded by construction: at most MaxInflight tasks exist at any
// time (dispatch blocks otherwise), each worker owns one body buffer capped
// by the body size limit, and every long-lived map is an LRU.
package engine

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theLabXHQ/pulse/internal/asn"
	"github.com/theLabXHQ/pulse/internal/cdn"
	"github.com/theLabXHQ/pulse/internal/extract"
	"github.com/theLabXHQ/pulse/internal/input"
	"github.com/theLabXHQ/pulse/internal/lru"
	"github.com/theLabXHQ/pulse/internal/match"
	"github.com/theLabXHQ/pulse/internal/output"
	"github.com/theLabXHQ/pulse/internal/probe"
	"github.com/theLabXHQ/pulse/internal/target"
	"github.com/theLabXHQ/pulse/internal/version"
)

// Config configures an Engine.
type Config struct {
	Workers            int
	MaxInflight        int     // tasks dispatched but not finished; default 4*Workers
	PerHostConcurrency int     // 0 = unlimited
	RateLimit          float64 // requests/second across all hosts; 0 = unlimited
	PerHostRate        float64 // requests/second per host; 0 = unlimited
	MaxHostErrors      int     // consecutive connection failures per host:port before skipping; 0 = off

	Ports       []target.PortSpec
	Paths       []string
	Methods     []string
	BothSchemes bool // probe HTTPS and HTTP independently (-no-fallback)
	Dedupe      bool

	Rules          *match.Rules
	IncludeFailed  bool
	Hashes         []string
	IncludeHeaders bool
	IncludeBody    bool
	Favicon        bool
	Tech           bool
	CDN            bool    // look up cdn/waf/cloud provider of the connected IP
	CDNDB          *cdn.DB // overrides the embedded ranges (tests)
	// ExcludeCDN probes only ports 80 and 443 of CDN/WAF addresses (-ec):
	// edges answer the same on every port. Cloud ranges are not excluded.
	ExcludeCDN       bool
	Discover         DiscoverConfig
	Adaptive         bool                      // per-host AIMD on 429/503/timeouts (see adaptive.go)
	VHost            bool                      // detect Host-header routing (enrichment stage, see vhost.go)
	Pipeline         bool                      // detect HTTP/1.1 pipelining support (enrichment stage)
	BodyPreview      int                       // -bp: first N characters of the body
	Extract          map[string]*regexp.Regexp // -er/-ep: name (regex or preset) -> pattern
	FilterDuplicates bool                      // -fd: drop near-duplicate responses from the same IP
	FilterErrorPage  bool                      // -fep
	Exclude          ExcludeRules              // -e
	Delay            time.Duration             // -delay: pause before each request
	CNAME            bool                      // -cname (enrichment)
	ASN              asn.Source                // AS lookup of the connected IP (enrichment stage); nil = off
	EnrichWorkers    int
	StoreDir         string

	StartLine int64                                // first input line (resume)
	Logf      func(level, format string, a ...any) // diagnostics; may be nil
}

// Stats are live counters, safe to read concurrently.
type Stats struct {
	Lines, Targets, Tasks, Requests  atomic.Int64
	Alive, Failed, Filtered, Written atomic.Int64
	Invalid, Duplicates, Skipped     atomic.Int64
	Discovered                       atomic.Int64 // names queued by -tls-probe/-csp-probe
	classMu                          sync.Mutex
	byClass                          map[probe.Class]int64
}

// ByClass returns a copy of failure counts per error class.
func (s *Stats) ByClass() map[probe.Class]int64 {
	s.classMu.Lock()
	defer s.classMu.Unlock()
	out := make(map[probe.Class]int64, len(s.byClass))
	for k, v := range s.byClass {
		out[k] = v
	}
	return out
}

func (s *Stats) addClass(c probe.Class) {
	s.classMu.Lock()
	s.byClass[c]++
	s.classMu.Unlock()
}

type task struct {
	line    int64
	input   string
	spec    probe.Spec
	hostKey string
	host    *hostState
	depth   int    // 0 for input targets, n for names discovered n hops away
	via     string // discovery source ("tls:<host>"), "" for input targets
	emitted bool   // a result went to the writer; it marks the line done once flushed
}

type enrichJob struct {
	t      *task
	res    *output.Result
	body   []byte
	header http.Header
	status string
}

// Engine runs probes. Create with New, run once with Run.
type Engine struct {
	cfg      Config
	client   *probe.Client
	out      chan<- *output.Result
	hosts    *hostLimiter
	pace     *pacer
	breaker  *lru.Cache[string, int]
	track    *tracker
	tech     extract.TechDetector
	cdn      *cdn.DB // nil unless Config.CDN
	disc     *discoverer
	adapt    *adaptive
	glob     *globalCtl
	dup      *dupFilter
	seen     map[uint64]struct{}
	inflight chan struct{}
	Stats    Stats
}

type paceKey struct{}

// New creates an Engine writing results to out. The caller owns out and must
// close it after Run returns.
func New(cfg Config, client *probe.Client, out chan<- *output.Result) *Engine {
	if cfg.Workers <= 0 {
		cfg.Workers = 50
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = 4 * cfg.Workers
	}
	if cfg.MaxInflight < cfg.Workers {
		cfg.MaxInflight = cfg.Workers
	}
	if len(cfg.Methods) == 0 {
		cfg.Methods = []string{http.MethodGet}
	}
	if cfg.EnrichWorkers <= 0 {
		cfg.EnrichWorkers = max(4, cfg.Workers/4)
	}
	if cfg.Rules == nil {
		cfg.Rules = &match.Rules{}
	}
	e := &Engine{
		cfg:      cfg,
		client:   client,
		out:      out,
		pace:     newPacer(cfg.RateLimit),
		track:    newTracker(cfg.StartLine),
		seen:     make(map[uint64]struct{}),
		inflight: make(chan struct{}, cfg.MaxInflight),
	}
	if cfg.FilterDuplicates {
		e.dup = newDupFilter()
	}
	if cfg.Discover.TLS || cfg.Discover.CSP {
		e.disc = newDiscoverer(cfg.Discover)
	}
	if cfg.CDN && cfg.CDNDB != nil {
		e.cdn = cfg.CDNDB
	} else if cfg.CDN {
		db, err := cdn.Default()
		if err != nil {
			e.logf("warn", "cdn detection unavailable: %v", err)
		}
		e.cdn = db
	}
	e.Stats.byClass = make(map[probe.Class]int64)
	if cfg.PerHostConcurrency > 0 || cfg.PerHostRate > 0 || cfg.Adaptive {
		e.hosts = newHostLimiter(cfg.PerHostConcurrency, cfg.PerHostRate)
	}
	if cfg.Adaptive {
		e.adapt = newAdaptive(cfg.PerHostConcurrency)
		e.hosts.limitFor = e.adapt.limit
		e.hosts.ready = make(chan *task, cfg.MaxInflight)
		e.glob = newGlobalCtl(cfg.Workers, e.logf)
	}
	if cfg.MaxHostErrors > 0 {
		e.breaker = lru.New[string, int](100000)
	}
	return e
}

// BeforeAttempt is installed as the probe client's hook: it applies the
// global and per-host rate limits to every scheme attempt and retry.
func (e *Engine) BeforeAttempt(ctx context.Context) error {
	if err := e.pace.Wait(ctx); err != nil {
		return err
	}
	if p, _ := ctx.Value(paceKey{}).(*pacer); p != nil {
		if err := p.Wait(ctx); err != nil {
			return err
		}
	}
	if d := e.cfg.Delay; d > 0 {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
	if s, _ := ctx.Value(adaptKey{}).(*adaptState); s != nil {
		if err := e.adapt.wait(ctx, s); err != nil {
			return err
		}
	}
	e.Stats.Requests.Add(1)
	return nil
}

// Watermark returns the first input line that is not yet complete.
func (e *Engine) Watermark() int64 { return e.track.watermark() }

func (e *Engine) logf(level, format string, a ...any) {
	if e.cfg.Logf != nil {
		e.cfg.Logf(level, format, a...)
	}
}

// Run consumes lines until the channel closes or dispatchCtx ends, then
// waits for in-flight work. workCtx aborts in-flight requests when canceled.
// Two contexts give the two-stage Ctrl+C: stop dispatching, then abort.
func (e *Engine) Run(dispatchCtx, workCtx context.Context, lines <-chan input.Line) {
	tasks := make(chan *task, e.cfg.Workers)
	var enrich chan *enrichJob
	if e.cfg.Favicon || e.cfg.Tech || e.cfg.ASN != nil || e.cfg.VHost || e.cfg.Pipeline || e.cfg.CNAME {
		enrich = make(chan *enrichJob, e.cfg.EnrichWorkers*2)
	}

	var wg sync.WaitGroup
	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.worker(dispatchCtx, workCtx, tasks, enrich)
		}()
	}
	var ewg sync.WaitGroup
	if enrich != nil {
		for i := 0; i < e.cfg.EnrichWorkers; i++ {
			ewg.Add(1)
			go func() {
				defer ewg.Done()
				buf := new(bytes.Buffer)
				for j := range enrich {
					e.enrich(workCtx, j, buf)
					buf = trimBuf(buf)
				}
			}()
		}
	}

	var wake <-chan struct{}
	if e.disc != nil {
		wake = e.disc.wake
	}
dispatch:
	for {
		// With discovery, input exhaustion is not the end: running tasks may
		// still queue names. Nothing can be queued once no task is in
		// flight, so check that first, then the queue.
		if lines == nil && (e.disc == nil || (len(e.inflight) == 0 && e.disc.empty())) {
			break
		}
		select {
		case <-dispatchCtx.Done():
			break dispatch
		case l, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			if !e.dispatchLine(dispatchCtx, l, tasks) {
				break dispatch
			}
		case <-wake:
			for _, x := range e.disc.drain() {
				if !e.dispatchDiscovered(dispatchCtx, x, tasks) {
					break dispatch
				}
			}
		}
	}
	close(tasks)
	wg.Wait()
	if enrich != nil {
		close(enrich)
		ewg.Wait()
	}
}

func (e *Engine) dispatchLine(ctx context.Context, l input.Line, tasks chan<- *task) bool {
	e.Stats.Lines.Add(1)
	e.track.start(l.Index)
	// A line is marked dispatched only once all its tasks exist. A line cut
	// short by an interrupt stays open, so the resume watermark never moves
	// past it and none of its targets can be lost.
	ok := e.dispatchLineTasks(ctx, l, tasks)
	if ok {
		e.track.dispatched(l.Index)
	}
	return ok
}

func (e *Engine) dispatchLineTasks(ctx context.Context, l input.Line, tasks chan<- *task) bool {
	text := strings.TrimSpace(l.Text)
	if text == "" || strings.HasPrefix(text, "#") {
		return true
	}
	if target.IsCIDR(text) {
		if e.cfg.Dedupe && e.isDuplicate("cidr|"+text) {
			e.Stats.Duplicates.Add(1)
			return true
		}
		ok := true
		err := target.ExpandCIDR(text, func(a netip.Addr) bool {
			ok = e.dispatchTarget(ctx, l.Index, target.Target{Input: text, Host: a.String()}, origin{}, tasks)
			return ok
		})
		if err != nil {
			e.Stats.Invalid.Add(1)
			e.logf("warn", "skipping %q: %v", text, err)
		}
		return ok
	}
	t, err := target.Parse(text)
	if err != nil {
		e.Stats.Invalid.Add(1)
		e.logf("warn", "skipping input line %d: %v", l.Index+1, err)
		return true
	}
	if e.cfg.Dedupe && e.isDuplicate(t.Key()) {
		e.Stats.Duplicates.Add(1)
		return true
	}
	return e.dispatchTarget(ctx, l.Index, t, origin{}, tasks)
}

// origin says how a target was found (zero for input targets).
type origin struct {
	depth int
	via   string
}

// dispatchDiscovered turns a queued name into tasks, then releases the
// placeholder that kept its input line open.
func (e *Engine) dispatchDiscovered(ctx context.Context, x discovery, tasks chan<- *task) bool {
	t, err := target.Parse(x.host)
	if err == nil && !(e.cfg.Dedupe && e.isDuplicate(t.Key())) {
		if !e.dispatchTarget(ctx, x.line, t, origin{depth: x.depth, via: x.via}, tasks) {
			return false // the line stays open; resume re-derives the name
		}
	}
	e.track.done(x.line)
	return true
}

// isDuplicate tracks 64-bit FNV-1a digests of keys (8 bytes + map overhead
// per unique target; collisions are astronomically unlikely below 1e9 keys).
func (e *Engine) isDuplicate(key string) bool {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	sum := h.Sum64()
	if _, ok := e.seen[sum]; ok {
		return true
	}
	e.seen[sum] = struct{}{}
	return false
}

func (e *Engine) dispatchTarget(ctx context.Context, line int64, t target.Target, o origin, tasks chan<- *task) bool {
	e.Stats.Targets.Add(1)
	type hp struct {
		port   int
		scheme string
	}
	var ports []hp
	if len(e.cfg.Ports) > 0 {
		for _, ps := range e.cfg.Ports {
			s := ps.Scheme
			if s == target.SchemeAuto {
				s = t.Scheme
			}
			ports = append(ports, hp{ps.Port, s})
		}
	} else {
		ports = []hp{{t.Port, t.Scheme}}
	}
	paths := []string{t.Path}
	if len(e.cfg.Paths) > 0 {
		paths = paths[:0]
		for _, p := range e.cfg.Paths {
			paths = append(paths, joinPath(t.Path, p))
		}
	}
	for _, p := range ports {
		schemes := []string{p.scheme}
		if e.cfg.BothSchemes && p.scheme == target.SchemeAuto {
			schemes = []string{target.SchemeHTTPS, target.SchemeHTTP}
		}
		for _, scheme := range schemes {
			for _, path := range paths {
				for _, m := range e.cfg.Methods {
					tk := &task{
						line:    line,
						input:   t.Input,
						spec:    probe.Spec{Host: t.Host, Port: p.port, Scheme: scheme, Path: path, Method: m, Auth: t.Auth},
						hostKey: t.Host,
						depth:   o.depth,
						via:     o.via,
					}
					select {
					case e.inflight <- struct{}{}:
					case <-ctx.Done():
						return false
					}
					e.track.add(line)
					e.Stats.Tasks.Add(1)
					select {
					case tasks <- tk:
					case <-ctx.Done():
						<-e.inflight // never ran: free the slot but leave the line incomplete
						return false
					}
				}
			}
		}
	}
	return true
}

func joinPath(base, p string) string {
	if base == "" || base == "/" {
		if !strings.HasPrefix(p, "/") {
			return "/" + p
		}
		return p
	}
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(p, "/")
}

// finish marks a task complete for resume accounting and frees its slot.
// A task whose result went to the writer is marked done by the writer once
// that result is flushed, so a resume point never covers unwritten output.
func (e *Engine) finish(t *task) {
	if !t.emitted {
		e.track.done(t.line)
	}
	e.release()
}

// abort frees the slot of a task that was interrupted (Ctrl+C) before it
// completed. Its line stays open, so a resumed run probes it again.
func (e *Engine) abort(*task) { e.release() }

func (e *Engine) release() {
	<-e.inflight
	if e.disc != nil {
		e.disc.signal() // the dispatcher may be waiting for the last task
	}
}

// worker runs tasks. After the first Ctrl+C (dispatchCtx done) it starts
// no new probe: queued and parked tasks are released unprobed with their
// lines open, so the run stops after the probes already in flight and a
// resume picks the rest up.
// maxKeptBuf is the largest body buffer a worker keeps between targets.
// Buffers grow to the largest body seen (up to -rstr); keeping that for
// every worker held ~70 MB at -t 50 on real sites, where most pages are
// far smaller.
const maxKeptBuf = 256 << 10

func trimBuf(b *bytes.Buffer) *bytes.Buffer {
	if b.Cap() > maxKeptBuf {
		return new(bytes.Buffer)
	}
	return b
}

func (e *Engine) worker(dispatchCtx, ctx context.Context, tasks <-chan *task, enrich chan<- *enrichJob) {
	buf := new(bytes.Buffer)
	runOne := func(t *task) {
		if dispatchCtx.Err() != nil {
			e.abort(t)
			return
		}
		e.run(ctx, t, buf, enrich)
		buf = trimBuf(buf)
	}
	chain := func(t *task) { // t holds a host slot; run it and whatever the slot passes on
		for t != nil {
			runOne(t)
			t = e.hosts.release(t)
		}
	}
	var ready <-chan *task
	if e.hosts != nil {
		ready = e.hosts.ready
	}
	for {
		select {
		case t := <-ready:
			chain(t)
			continue
		default:
		}
		select {
		case t := <-ready:
			chain(t)
		case t, ok := <-tasks:
			if !ok {
				// Input is done, but tasks parked on hosts may still be
				// started (put on ready) by other workers' releases; stay
				// to run them in parallel until nothing is parked.
				for {
					select {
					case t := <-ready:
						chain(t)
						continue
					default:
					}
					if e.hosts == nil || ready == nil || e.hosts.idle() {
						return
					}
					select {
					case t := <-ready:
						chain(t)
					case <-time.After(10 * time.Millisecond):
					}
				}
			}
			if e.hosts == nil {
				runOne(t)
				continue
			}
			if e.hosts.acquire(t) {
				chain(t)
			} // else parked; a worker releasing this host will run it
		}
	}
}

// skipCDNPort implements -ec. The lookup uses the shared DNS cache, so the
// probe that follows does not resolve again; resolution errors are left to
// the probe to report.
func (e *Engine) skipCDNPort(ctx context.Context, t *task) bool {
	if !e.cfg.ExcludeCDN || e.cdn == nil || e.client.Proxied() {
		return false
	}
	if p := t.spec.Port; p == 0 || p == 80 || p == 443 {
		return false
	}
	ips, err := e.client.Resolve(ctx, t.spec.Host)
	if err != nil || len(ips) == 0 {
		return false
	}
	m, ok := e.cdn.Lookup(ips[0])
	return ok && (m.Type == "cdn" || m.Type == "waf")
}

func (e *Engine) breakerKey(s probe.Spec) string {
	return s.Host + "|" + strconv.Itoa(s.Port) + "|" + s.Scheme
}

func (e *Engine) run(ctx context.Context, t *task, buf *bytes.Buffer, enrich chan<- *enrichJob) {
	handedOff, aborted := false, false
	defer func() {
		switch {
		case aborted:
			e.abort(t)
		case !handedOff:
			e.finish(t)
		}
		// Don't let one huge body pin memory for the rest of the run.
		if buf.Cap() > 4<<20 {
			*buf = bytes.Buffer{}
		}
	}()

	key := ""
	if e.breaker != nil {
		key = e.breakerKey(t.spec)
		if n, ok := e.breaker.Get(key); ok && n >= e.cfg.MaxHostErrors {
			e.Stats.Skipped.Add(1)
			e.fail(t, &probe.Failure{
				Error: &probe.Error{Class: probe.ClassHostSkipped, Phase: probe.PhaseConnect,
					Err: fmt.Errorf("skipped after %d consecutive connection failures", n)},
				URL: target.BuildURL(firstScheme(t.spec), t.spec.Host, t.spec.Port, t.spec.Path),
			})
			return
		}
	}

	if e.excluded(ctx, t) {
		e.Stats.Skipped.Add(1) // -e: silently not probed
		return
	}
	if e.skipCDNPort(ctx, t) {
		e.Stats.Skipped.Add(1)
		e.fail(t, &probe.Failure{
			Error: &probe.Error{Class: probe.ClassCDNPortSkipped, Phase: probe.PhasePolicy,
				Err: fmt.Errorf("port %d of a CDN/WAF address (-ec)", t.spec.Port)},
			URL: target.BuildURL(firstScheme(t.spec), t.spec.Host, t.spec.Port, t.spec.Path),
		})
		return
	}

	pctx := ctx
	if t.host != nil && t.host.pace != nil {
		pctx = context.WithValue(ctx, paceKey{}, t.host.pace)
	}
	if e.adapt != nil {
		pctx = context.WithValue(pctx, adaptKey{}, e.adapt.state(t.hostKey))
	}
	if e.glob != nil {
		if err := e.glob.acquire(ctx); err != nil {
			aborted = true
			return
		}
	}
	r, f := e.client.Probe(pctx, t.spec, buf)
	if f != nil && f.Class == probe.ClassCanceled && ctx.Err() != nil {
		// Interrupted, not answered: no result, and the line stays open
		// for -resume. (Releasing the global slot happens below.)
		if e.glob != nil {
			e.glob.release()
		}
		aborted = true
		return
	}
	if e.glob != nil {
		e.glob.release()
		e.glob.observe(r, f)
	}
	if e.adapt != nil {
		e.adapt.observe(t.hostKey, r, f)
	}

	if e.breaker != nil {
		switch {
		case f == nil:
			e.breaker.Delete(key)
		case f.ConnectionLevel() && !f.HostLevel():
			e.breaker.Update(key, func(n int, _ bool) int { return n + 1 })
		}
	}
	if f != nil {
		e.fail(t, f)
		return
	}
	e.discover(t, r) // before any filter: a filtered page's certificate still names hosts
	e.Stats.Alive.Add(1)

	res := e.buildResult(t, r)
	rawHeaders := ""
	if e.cfg.Rules.NeedsBody() || e.cfg.StoreDir != "" || len(e.cfg.Extract) > 0 {
		rawHeaders = headerBlock(r)
	}
	// String matchers, DSL and -irr see the body in UTF-8 (a windows-1251
	// page must match -ms 'привет'); tech detection and -sr keep raw bytes.
	text := r.Body
	if e.cfg.Rules.NeedsBody() || e.cfg.Rules.HasDSL() || e.cfg.IncludeBody || e.cfg.BodyPreview > 0 || len(e.cfg.Extract) > 0 {
		text = extract.BodyUTF8(r.Body, r.Header.Get("Content-Type"))
	}
	res.BodyPreview = bodyPreview(text, e.cfg.BodyPreview)
	res.Extracts = e.extracts(rawHeaders, text)
	if !e.cfg.Rules.Keep(match.Input{
		StatusCode: r.StatusCode, ContentLength: res.ContentLength, Lines: res.Lines, Words: res.Words,
		Headers: []byte(rawHeaders), Body: text, CDNName: res.CDNName, CDNType: res.CDNType,
		Seconds: r.Timing.Total / 1000,
	}) {
		e.Stats.Filtered.Add(1)
		return
	}
	// -mdc/-fdc see enrichment fields (tech, favicon, asn), so with an
	// enrichment stage they are evaluated there instead.
	if enrich == nil && e.cfg.Rules.HasDSL() && !e.cfg.Rules.KeepDSL(varsFor(res, text, r.Header)) {
		e.Stats.Filtered.Add(1)
		return
	}
	if (e.cfg.FilterErrorPage && errorPage(res)) || (e.dup != nil && e.dup.duplicate(r.Body, res.IP)) {
		e.Stats.Filtered.Add(1)
		return
	}
	if e.cfg.IncludeBody {
		res.Body = string(text)
	}
	if enrich != nil {
		j := &enrichJob{t: t, res: res, body: bytes.Clone(r.Body), header: r.Header, status: rawHeaders}
		select {
		case enrich <- j:
			handedOff = true
		case <-ctx.Done():
			aborted = true // not filtered or enriched yet: do not emit it half-done
		}
		return
	}
	if e.cfg.StoreDir != "" {
		e.store(res, rawHeaders, r.Body)
	}
	e.emit(t, res)
}

func firstScheme(s probe.Spec) string {
	if s.Scheme == target.SchemeHTTP || s.Scheme == target.SchemeHTTPS {
		return s.Scheme
	}
	return target.SchemeOrder(s.Port)[0]
}

func (e *Engine) fail(t *task, f *probe.Failure) {
	e.Stats.Failed.Add(1)
	e.Stats.addClass(f.Class)
	e.logf("verbose", "%s: %s (%s) %v", t.input, f.Class, f.Phase, f.Err)
	if !e.cfg.IncludeFailed || e.cfg.Rules.HasFaviconRules() {
		return
	}
	if !e.cfg.Rules.Empty() && !e.cfg.Rules.Keep(match.Input{}) {
		return
	}
	res := &output.Result{
		Schema:         version.SchemaVersion,
		Timestamp:      time.Now().UTC(),
		Input:          t.input,
		DiscoveredFrom: t.via,
		URL:            f.URL,
		Host:           t.spec.Host,
		Port:           t.spec.Port,
		Path:           t.spec.Path,
		Method:         t.spec.Method,
		Timing:         f.Timing,
		Attempts:       f.Attempts,
		Failed:         true,
		Error:          &output.ErrorInfo{Class: f.Class, Phase: f.Phase, Message: f.Err.Error()},
	}
	e.emit(t, res)
}

// emit hands a result to the writer. The send blocks while the writer's
// queue is full: that is the backpressure path and it never drops results.
func (e *Engine) emit(t *task, res *output.Result) {
	t.emitted = true
	line := t.line
	res.OnWritten = func() { e.track.done(line) }
	e.out <- res
	e.Stats.Written.Add(1)
}

func (e *Engine) enrich(ctx context.Context, j *enrichJob, buf *bytes.Buffer) {
	defer func() {
		if ctx.Err() != nil && !j.t.emitted {
			e.abort(j.t) // interrupted mid-enrichment: probe it again on resume
			return
		}
		e.finish(j.t)
	}()
	if e.cfg.Tech {
		tech, err := e.tech.Detect(j.header, j.body)
		if err != nil {
			e.logf("warn", "tech detection unavailable: %v", err)
		}
		j.res.Tech = tech
	}
	if e.cfg.ASN != nil && j.res.IP != "" {
		if ip, err := netip.ParseAddr(j.res.IP); err == nil {
			actx, cancel := context.WithTimeout(ctx, 10*time.Second)
			info, err := e.cfg.ASN.Lookup(actx, ip)
			cancel()
			switch {
			case err != nil:
				j.res.Warnings = append(j.res.Warnings, "asn_lookup_failed")
			case info != nil:
				j.res.ASN = &output.ASNInfo{AsNumber: "AS" + strconv.Itoa(info.Number), AsName: info.Name,
					AsCountry: info.Country, AsRange: info.Ranges}
			}
		}
	}
	if e.cfg.CNAME {
		j.res.CNAME = e.client.CNAME(ctx, j.res.Host)
	}
	if e.cfg.VHost {
		j.res.VHost = e.vhost(ctx, j.res, buf)
	}
	if e.cfg.Pipeline && e.BeforeAttempt(ctx) == nil {
		j.res.Pipeline = e.client.Pipeline(ctx, j.res.Scheme, j.res.Host, j.res.Port)
	}
	if e.cfg.Favicon {
		page := j.res.URL
		if j.res.FinalURL != "" {
			page = j.res.FinalURL
		}
		j.res.Favicon = e.favicon(ctx, page, j.body, buf)
	}
	if e.cfg.Rules.HasFaviconRules() {
		mmh3 := ""
		if j.res.Favicon != nil {
			mmh3 = j.res.Favicon.MMH3
		}
		if !e.cfg.Rules.KeepFavicon(mmh3) {
			e.Stats.Filtered.Add(1)
			return
		}
	}
	if e.cfg.Rules.HasDSL() && !e.cfg.Rules.KeepDSL(varsFor(j.res, extract.BodyUTF8(j.body, j.header.Get("Content-Type")), j.header)) {
		e.Stats.Filtered.Add(1)
		return
	}
	if e.cfg.StoreDir != "" {
		e.store(j.res, j.status, j.body)
	}
	if ctx.Err() != nil {
		return // enrichment was cut short; the deferred abort keeps the line open
	}
	e.emit(j.t, j.res)
}
