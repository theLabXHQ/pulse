package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/theLabXHQ/pulse/internal/asn"
	"github.com/theLabXHQ/pulse/internal/cdn"
	"github.com/theLabXHQ/pulse/internal/dns"
	"github.com/theLabXHQ/pulse/internal/engine"
	"github.com/theLabXHQ/pulse/internal/input"
	"github.com/theLabXHQ/pulse/internal/logx"
	"github.com/theLabXHQ/pulse/internal/output"
	"github.com/theLabXHQ/pulse/internal/probe"
	"github.com/theLabXHQ/pulse/internal/version"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitInterrupted = 130
)

// Env abstracts process I/O so Main can be tested.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	StdinPiped     bool
	StdoutTTY      bool
	StderrTTY      bool             // the banner is shown only on a terminal
	Signals        <-chan os.Signal // nil installs SIGINT/SIGTERM handlers
	CDN            *cdn.DB          // nil uses the embedded CDN/WAF/cloud ranges
	ASN            asn.Source       // overrides the -asn source (tests)
}

// Main runs pulse with args and returns the exit code.
func Main(args []string, env Env) int {
	o, err := parse(args, env.Stderr)
	if err != nil {
		var h *helpRequest
		if errors.As(err, &h) {
			color := env.StdoutTTY && !slices.ContainsFunc(args, func(a string) bool {
				return a == "-nc" || a == "--nc" || a == "-no-color" || a == "--no-color"
			})
			if h.full {
				h.r.usage(env.Stdout, color)
			} else {
				h.r.shortUsage(env.Stdout, color)
			}
			return ExitOK
		}
		fmt.Fprintf(env.Stderr, "pulse: %v (see pulse -h)\n", err)
		return ExitUsage
	}
	if o.Version {
		fmt.Fprintf(env.Stdout, "pulse %s (schema %s)\n", version.Version, version.SchemaVersion)
		return ExitOK
	}
	if err := o.validate(); err != nil {
		fmt.Fprintf(env.Stderr, "pulse: %v\n", err)
		return ExitUsage
	}
	if !o.Silent && env.StderrTTY {
		printBanner(env.Stderr, !o.NoColor)
	}
	log := logx.New(env.Stderr)
	log.Verbose, log.Silent, log.Color = o.Verbose, o.Silent, !o.NoColor && env.StdoutTTY
	if (o.IncludeBody || o.IncludeHeaders) && !o.JSON && !o.CSV {
		log.Logf("warn", "-irr/-irh add fields to JSON output only (use -j)")
	}

	src := input.Source{Targets: o.Targets, Files: o.Lists, Format: o.InputMode,
		OnSkip: func(source string, line int64) {
			log.Logf("warn", "skipping %s line %d: longer than %d KiB", source, line+1, input.MaxLineLen>>10)
		}}
	usesStdin := false
	for _, f := range o.Lists {
		usesStdin = usesStdin || f == "-"
	}
	// Stdin is read when explicitly requested, or when it is the only input:
	// never implicitly in addition to -u/-l, which would hang scripts that
	// inherit an open stdin.
	if !o.NoStdin && (usesStdin || (len(o.Targets) == 0 && len(o.Lists) == 0 && env.StdinPiped)) {
		src.Stdin = env.Stdin
	}
	if len(o.Targets) == 0 && len(o.Lists) == 0 && src.Stdin == nil {
		fmt.Fprintf(env.Stderr, "pulse: no input; use -u, -l or pipe targets on stdin (see pulse -h)\n")
		return ExitUsage
	}
	for _, f := range o.Lists {
		if f == "-" {
			continue
		}
		if _, err := os.Stat(f); err != nil {
			fmt.Fprintf(env.Stderr, "pulse: %v\n", err)
			return ExitUsage
		}
	}

	var startLine int64
	if o.Resume != "" {
		cp, err := engine.LoadCheckpoint(o.Resume)
		if err != nil {
			fmt.Fprintf(env.Stderr, "pulse: %v\n", err)
			return ExitError
		}
		startLine = cp.NextLine
		if startLine > 0 {
			log.Logf("info", "resuming from input line %d (%s)", startLine+1, o.Resume)
		}
	}

	if o.CPUProfile != "" {
		f, err := os.Create(o.CPUProfile)
		if err != nil {
			fmt.Fprintf(env.Stderr, "pulse: %v\n", err)
			return ExitError
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintf(env.Stderr, "pulse: %v\n", err)
			return ExitError
		}
		defer func() { pprof.StopCPUProfile(); _ = f.Close() }()
	}
	if o.MemProfile != "" {
		defer func() {
			f, err := os.Create(o.MemProfile)
			if err != nil {
				log.Logf("error", "memprofile: %v", err)
				return
			}
			runtime.GC()
			_ = pprof.WriteHeapProfile(f)
			_ = f.Close()
		}()
	}
	return execute(o, env, log, src, startLine)
}

func keepAlive(o *Options) bool {
	switch o.KeepAlive {
	case "on":
		return true
	case "off":
		return false
	}
	return len(o.portSpecs) > 1 || len(o.pathList) > 1 || len(o.methods) > 1 || o.Fields.Favicon || o.NoFallback
}

// defaultFallbackResolvers replace a system resolver that does not answer
// (e.g. WSL's DNS proxy after the host's network changed).
var defaultFallbackResolvers = []string{"1.1.1.1", "8.8.8.8"}

func execute(o *Options, env Env, log *logx.Logger, src input.Source, startLine int64) int {
	dnsOpts := dns.Options{Servers: o.Resolvers, Timeout: min(o.Timeout, 5*time.Second)}
	if len(o.Resolvers) == 0 && !o.NoDNSFallback {
		dnsOpts.Fallback = defaultFallbackResolvers
		dnsOpts.OnFallback = func(reason string) {
			log.Logf("warn", "DNS: %s; switching to %s (choose servers with -r, disable with -no-dns-fallback)",
				reason, strings.Join(defaultFallbackResolvers, ", "))
		}
	}
	// The system resolver is checked in the background on the first name
	// lookup: probing starts at once, IP-only runs never check, and names
	// it drops meanwhile are retried on the fallback anyway.
	dnsOpts.AutoCheck = true
	resolver := dns.New(dnsOpts)

	var eng *engine.Engine
	client, err := probe.New(probe.Options{
		Timeout:             o.Timeout,
		Retries:             o.Retries,
		FollowRedirects:     o.FollowRedirects,
		FollowHostRedirects: o.FollowHost,
		MaxRedirects:        o.MaxRedirects,
		MaxBodySize:         o.MaxBody,
		Body:                o.Body,
		Raw:                 o.raw,
		Headers:             o.header,
		UserAgent:           o.header.Get("User-Agent"),
		Proxy:               o.Proxy,
		HTTP2:               o.HTTP2,
		Impersonate:         o.Impersonate,
		RandomAgent:         o.RandomAgent,
		LeaveDefaultPorts:   o.LeaveDefaultPorts,
		KeepAlive:           keepAlive(o),
		MaxIdleConns:        o.Threads * 2,
		SNI:                 o.SNI,
		Deny:                o.deny,
		Resolver:            resolver,
		BeforeAttempt:       func(ctx context.Context) error { return eng.BeforeAttempt(ctx) },
	})
	if err != nil {
		fmt.Fprintf(env.Stderr, "pulse: %v\n", err)
		return ExitUsage
	}
	defer client.Close()

	var asnSrc asn.Source
	switch {
	case env.ASN != nil && o.Fields.ASN:
		asnSrc = env.ASN
	case o.ASNDB != "":
		db, err := asn.LoadFile(o.ASNDB)
		if err != nil {
			fmt.Fprintf(env.Stderr, "pulse: -asn-db: %v\n", err)
			return ExitUsage
		}
		asnSrc = db
	case o.Fields.ASN:
		asnSrc = asn.NewCymru(resolver.LookupTXT)
		log.Logf("info", "-asn: using Team Cymru DNS (origin.asn.cymru.com); the probed IPs are sent to Team Cymru. "+
			"Use -asn-db FILE (https://iptoasn.com) for offline lookups")
	}

	var outFile *os.File
	if o.Output != "" {
		if outFile, err = os.Create(o.Output); err != nil {
			fmt.Fprintf(env.Stderr, "pulse: %v\n", err)
			return ExitError
		}
		defer outFile.Close()
	}

	dispatchCtx, stopDispatch := context.WithCancel(context.Background())
	workCtx, abortWork := context.WithCancel(context.Background())
	defer stopDispatch()
	defer abortWork()

	var writeErr error
	var writeErrOnce sync.Once
	wcfg := output.Config{
		Format: output.FormatPlain,
		Fields: o.Fields,
		Color:  !o.NoColor && env.StdoutTTY,
		Stdout: env.Stdout,
		OnError: func(err error) {
			writeErrOnce.Do(func() {
				writeErr = err
				stopDispatch()
				abortWork()
			})
		},
	}
	if outFile != nil {
		wcfg.File = outFile
	}
	switch {
	case o.JSON:
		wcfg.Format = output.FormatJSONL
	case o.CSV:
		wcfg.Format = output.FormatCSV
	}
	writer := output.New(wcfg, 1024)

	storeDir := ""
	if o.StoreResponse {
		storeDir = o.StoreDir
	}
	eng = engine.New(engine.Config{
		Workers:            o.Threads,
		PerHostConcurrency: o.HostConcurrency,
		RateLimit:          o.RateLimit,
		PerHostRate:        o.RateLimitHost,
		MaxHostErrors:      o.MaxHostErrors,
		Ports:              o.portSpecs,
		Paths:              o.pathList,
		Methods:            o.methods,
		BothSchemes:        o.NoFallback,
		Dedupe:             !o.NoDedupe,
		Rules:              o.rules,
		IncludeFailed:      o.Fields.Probe,
		Hashes:             o.hashes,
		IncludeHeaders:     o.IncludeHeaders,
		IncludeBody:        o.IncludeBody,
		Favicon:            o.Fields.Favicon,
		Tech:               o.Fields.Tech,
		CDN:                o.Fields.CDN || o.JSON || o.CSV || o.rules.HasCDNRules() || o.ExcludeCDN,
		ExcludeCDN:         o.ExcludeCDN,
		ASN:                asnSrc,
		Adaptive:           o.Adaptive,
		VHost:              o.Fields.VHost,
		BodyPreview:        o.BodyPreview,
		Extract:            o.extract,
		FilterDuplicates:   o.FilterDuplicates,
		FilterErrorPage:    o.FilterErrorPage,
		Exclude:            o.exclude,
		Delay:              o.Delay,
		CNAME:              o.Fields.CNAME,
		Pipeline:           o.Fields.Pipeline,
		Discover: engine.DiscoverConfig{TLS: o.TLSProbe, CSP: o.CSPProbe, AnyScope: o.DiscoverScope == "any",
			MaxDepth: o.DiscoverDepth, MaxTargets: o.DiscoverMax},
		CDNDB:         env.CDN,
		EnrichWorkers: o.EnrichThreads,
		StoreDir:      storeDir,
		StartLine:     startLine,
		Logf:          log.Logf,
	}, client, writer.In())

	// Two-stage interrupt: stop dispatching (in-flight probes finish and are
	// written), then abort in-flight requests, then exit immediately.
	interrupted := false
	var intMu sync.Mutex
	sigs := env.Signals
	if sigs == nil {
		ch := make(chan os.Signal, 3)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(ch)
		sigs = ch
	}
	sigDone := make(chan struct{})
	defer close(sigDone)
	go func() {
		n := 0
		for {
			select {
			case <-sigDone:
				return
			case <-sigs:
				n++
				intMu.Lock()
				interrupted = true
				intMu.Unlock()
				switch n {
				case 1:
					log.Logf("warn", "interrupt: finishing in-flight probes (Ctrl+C again to abort them)")
					stopDispatch()
				case 2:
					log.Logf("warn", "interrupt: aborting in-flight probes")
					abortWork()
				default:
					os.Exit(ExitInterrupted)
				}
			}
		}
	}()

	writerDone := make(chan error, 1)
	go func() { writerDone <- writer.Run() }()

	lines := make(chan input.Line, 256)
	inputErr := make(chan error, 1)
	go func() {
		err := input.Stream(dispatchCtx, src, startLine, lines)
		close(lines)
		inputErr <- err
	}()

	stopStats := make(chan struct{})
	var statsWG sync.WaitGroup
	start := time.Now()
	if o.Stats {
		statsWG.Add(1)
		go func() {
			defer statsWG.Done()
			t := time.NewTicker(o.StatsInterval)
			defer t.Stop()
			for {
				select {
				case <-stopStats:
					return
				case <-t.C:
					printStats(log, eng, start)
				}
			}
		}()
	}
	stopCheckpoint := make(chan struct{})
	var cpWG sync.WaitGroup
	if o.Resume != "" {
		cpWG.Add(1)
		go func() {
			defer cpWG.Done()
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stopCheckpoint:
					return
				case <-t.C:
					if err := engine.SaveCheckpoint(o.Resume, engine.Checkpoint{NextLine: eng.Watermark()}); err != nil {
						log.Logf("error", "saving resume file: %v", err)
					}
				}
			}
		}()
	}

	eng.Run(dispatchCtx, workCtx, lines)
	stopDispatch() // unblock the input reader if it is still producing
	close(writer.In())
	wErr := <-writerDone
	inErr := <-inputErr
	close(stopStats)
	statsWG.Wait()
	close(stopCheckpoint)
	cpWG.Wait()

	intMu.Lock()
	wasInterrupted := interrupted
	intMu.Unlock()

	code := ExitOK
	if inErr != nil && !errors.Is(inErr, context.Canceled) {
		log.Logf("error", "input: %v", inErr)
		code = ExitError
	}
	if wErr != nil || writeErr != nil {
		if wErr == nil {
			wErr = writeErr
		}
		log.Logf("error", "output: %v", wErr)
		code = ExitError
	}
	if wasInterrupted && code == ExitOK {
		code = ExitInterrupted
	}

	if o.Resume != "" {
		if code == ExitOK {
			if err := os.Remove(o.Resume); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Logf("warn", "removing resume file: %v", err)
			}
		} else {
			wm := eng.Watermark()
			if err := engine.SaveCheckpoint(o.Resume, engine.Checkpoint{NextLine: wm}); err != nil {
				log.Logf("error", "saving resume file: %v", err)
			} else {
				log.Logf("info", "progress saved to %s (resume at input line %d)", o.Resume, wm+1)
			}
		}
	}
	if !o.Silent {
		printSummary(log, eng, resolver, time.Since(start))
	}
	return code
}

func printStats(log *logx.Logger, e *engine.Engine, start time.Time) {
	el := time.Since(start)
	s := &e.Stats
	req := s.Requests.Load()
	log.Printf("[%s] lines %d | targets %d | requests %d (%.0f/s) | alive %d | failed %d | filtered %d\n",
		el.Truncate(time.Second), s.Lines.Load(), s.Targets.Load(), req, float64(req)/el.Seconds(),
		s.Alive.Load(), s.Failed.Load(), s.Filtered.Load())
}

func printSummary(log *logx.Logger, e *engine.Engine, r *dns.CachingResolver, el time.Duration) {
	s := &e.Stats
	tasks := s.Tasks.Load()
	// Same palette as the result lines; the text without color is unchanged.
	paint := func(c string, v any) string {
		if !log.Color {
			return fmt.Sprint(v)
		}
		return c + fmt.Sprint(v) + "\x1b[0m"
	}
	const bold, dim, green, red = "\x1b[1m", "\x1b[2m", "\x1b[1;32m", "\x1b[1;31m"
	failed := s.Failed.Load()
	failedColor := dim
	if failed > 0 {
		failedColor = red
	}
	log.Printf("%s %s probes in %s (%.1f/s): %s alive, %s failed, %d filtered, %d requests, %d DNS lookups",
		paint(dim, "[pulse]"), paint(bold, tasks), el.Truncate(time.Millisecond), float64(tasks)/el.Seconds(),
		paint(green, s.Alive.Load()), paint(failedColor, failed),
		s.Filtered.Load(), s.Requests.Load(), r.Lookups())
	if n := s.Invalid.Load(); n > 0 {
		log.Printf(", %d invalid inputs", n)
	}
	if n := s.Duplicates.Load(); n > 0 {
		log.Printf(", %d duplicates", n)
	}
	log.Printf("\n")
	byClass := s.ByClass()
	if len(byClass) == 0 {
		return
	}
	type kv struct {
		k string
		v int64
	}
	var list []kv
	for k, v := range byClass {
		list = append(list, kv{string(k), v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v || list[i].v == list[j].v && list[i].k < list[j].k })
	parts := make([]string, len(list))
	for i, p := range list {
		parts[i] = fmt.Sprintf("%s=%d", p.k, p.v)
	}
	prefix := "[pulse]"
	if log.Color {
		prefix = "\x1b[2m[pulse]\x1b[0m"
	}
	log.Printf("%s failures: %s\n", prefix, strings.Join(parts, " "))
}
