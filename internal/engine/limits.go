package engine

import (
	"context"
	"sync"
	"time"
)

// pacer spaces events evenly at a fixed rate (no bursts). Each Wait reserves
// the next free slot, so concurrent callers queue fairly without a goroutine.
type pacer struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newPacer(perSecond float64) *pacer {
	if perSecond <= 0 {
		return nil
	}
	return &pacer{interval: time.Duration(float64(time.Second) / perSecond)}
}

// Wait blocks until the caller's slot. A nil pacer never blocks. If ctx ends
// first the reserved slot is simply skipped, which is harmless.
func (p *pacer) Wait(ctx context.Context) error {
	if p == nil {
		return ctx.Err()
	}
	p.mu.Lock()
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	at := p.next
	p.next = p.next.Add(p.interval)
	p.mu.Unlock()
	d := time.Until(at)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// hostState tracks concurrency, deferred tasks and pacing for one host.
type hostState struct {
	active  int
	waiting []*task
	pace    *pacer
}

// hostLimiter enforces per-host concurrency without ever blocking a worker:
// a task for a saturated host is parked on that host and handed to the
// worker that releases the host's next slot. Parked tasks are bounded by the
// engine's in-flight limit, so memory stays bounded.
type hostLimiter struct {
	mu       sync.Mutex
	limit    int
	limitFor func(host string) int // overrides limit (-adaptive); may be nil
	// ready receives parked tasks a release may start in addition to the
	// one it hands over, when the host's limit grew (-adaptive slow start).
	// Its capacity is the engine's in-flight bound, so sends never block.
	ready   chan *task
	parked  int // tasks waiting on any host
	perHost float64
	hosts   map[string]*hostState
}

func newHostLimiter(limit int, perHostRate float64) *hostLimiter {
	return &hostLimiter{limit: limit, perHost: perHostRate, hosts: make(map[string]*hostState)}
}

// acquire returns true if t may run now; otherwise t has been parked.
func (h *hostLimiter) acquire(t *task) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.hosts[t.hostKey]
	if st == nil {
		st = &hostState{pace: newPacer(h.perHost)}
		h.hosts[t.hostKey] = st
	}
	if lim := h.limitOf(t.hostKey); lim > 0 && st.active >= lim {
		st.waiting = append(st.waiting, t)
		h.parked++
		return false
	}
	st.active++
	t.host = st
	return true
}

func (h *hostLimiter) pop(st *hostState) *task {
	h.parked--
	t := st.waiting[0]
	st.waiting[0] = nil
	st.waiting = st.waiting[1:]
	t.host = st
	return t
}

// idle reports whether no task is parked on any host, i.e. no release can
// put more work on ready.
func (h *hostLimiter) idle() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.parked == 0
}

func (h *hostLimiter) limitOf(host string) int {
	if h.limitFor != nil {
		return h.limitFor(host)
	}
	return h.limit
}

// release frees t's slot and returns a parked task that now owns it, if any.
func (h *hostLimiter) release(t *task) *task {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.hosts[t.hostKey]
	// When the host's limit shrank (-adaptive), a freed slot is given up
	// instead of handed over — but never the last one, or parked tasks
	// would wait forever.
	if lim := h.limitOf(t.hostKey); len(st.waiting) > 0 && (lim <= 0 || st.active <= lim || st.active == 1) {
		next := h.pop(st)
		// The limit may have grown since these tasks were parked: start
		// as many more as it now allows.
		for h.ready != nil && len(st.waiting) > 0 && lim > 0 && st.active < lim {
			extra := h.pop(st)
			st.active++
			h.ready <- extra
		}
		return next
	}
	st.active--
	if st.active == 0 {
		delete(h.hosts, t.hostKey)
	}
	return nil
}
