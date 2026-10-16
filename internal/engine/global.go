package engine

import (
	"context"
	"slices"
	"sync"

	"github.com/theLabXHQ/pulse/internal/probe"
)

// globalCtl adapts the number of probes in flight (-adaptive) to local
// congestion: when the scanning machine or its uplink saturates (a laptop
// on Wi-Fi, WSL, a VPN), connections queue, connect times of successful
// probes rise and timeouts spread across hosts. Either signal alone is not
// enough — a list of dead hosts times out without any congestion, and
// latency varies between hosts — so the limit drops by a quarter only when
// both appear in the same window, and never below a quarter of -t. It
// recovers additively while connect times stay near the baseline: the
// lowest window median of the run (a sliding baseline would, under
// sustained congestion, adopt the congested latency as normal and ramp
// back up into it).
type globalCtl struct {
	mu     sync.Mutex
	cond   *sync.Cond
	limit  int
	max    int
	floor  int
	active int

	n, timeouts int
	connect     []float64 // connect_ms of successful probes in this window
	baseline    float64   // lowest window median so far; 0 = none yet
	logf        func(level, format string, a ...any)
}

const (
	congestionLatency  = 2.5  // window median / baseline
	congestionTimeouts = 0.20 // timeout share of a window
	recoverLatency     = 1.5
)

func newGlobalCtl(workers int, logf func(string, string, ...any)) *globalCtl {
	g := &globalCtl{limit: workers, max: workers, floor: max(1, workers/4), logf: logf}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// acquire blocks until a probe may start or ctx ends.
func (g *globalCtl) acquire(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() {
		g.mu.Lock()
		g.cond.Broadcast()
		g.mu.Unlock()
	})
	defer stop()
	g.mu.Lock()
	defer g.mu.Unlock()
	for g.active >= g.limit {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.cond.Wait()
	}
	g.active++
	return nil
}

func (g *globalCtl) release() {
	g.mu.Lock()
	g.active--
	g.cond.Signal()
	g.mu.Unlock()
}

func (g *globalCtl) window() int { return max(100, 2*g.limit) }

// observe records one probe outcome and re-evaluates at window ends.
func (g *globalCtl) observe(r *probe.Response, f *probe.Failure) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	switch {
	case f != nil && (f.Class == probe.ClassConnTimeout || f.Class == probe.ClassTLSTimeout || f.Class == probe.ClassResponseTimout):
		g.timeouts++
	case r != nil && r.Timing.Connect > 0 && len(g.connect) < 1024:
		g.connect = append(g.connect, r.Timing.Connect)
	}
	if g.n < g.window() {
		return
	}
	g.evaluate()
	g.n, g.timeouts, g.connect = 0, 0, g.connect[:0]
	g.cond.Broadcast()
}

func (g *globalCtl) evaluate() {
	share := float64(g.timeouts) / float64(g.n)
	if len(g.connect) < 10 {
		return // too few successes to judge latency
	}
	slices.Sort(g.connect)
	median := g.connect[len(g.connect)/2]
	if g.baseline == 0 || median < g.baseline {
		g.baseline = median
	}
	baseline := g.baseline
	switch {
	case median > congestionLatency*baseline && share > congestionTimeouts:
		if next := max(g.floor, g.limit*3/4); next < g.limit {
			g.limit = next
			if g.logf != nil {
				g.logf("info", "adaptive: congestion (connect %.0fms vs %.0fms, %.0f%% timeouts); concurrency %d", median, baseline, 100*share, g.limit)
			}
		}
	case median < recoverLatency*baseline && g.limit < g.max:
		g.limit = min(g.max, g.limit+max(1, g.max/20))
	}
}
