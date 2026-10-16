package engine

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/theLabXHQ/pulse/internal/lru"
	"github.com/theLabXHQ/pulse/internal/probe"
)

// Adaptive per-host pacing (-adaptive), driven only by the host's own
// signals, much like TCP congestion control:
//   - slow start: a host begins at one request at a time and gains one slot
//     per success until it first pushes back;
//   - a 429/503 or a timeout halves its concurrency (then +1 per window of
//     successes, up to -ch);
//   - a 429/503 also pauses the host for Retry-After (at most maxPause) and
//     doubles a minimum gap between its requests (rate-limiting WAFs count
//     requests per time window, which concurrency alone cannot respect);
//     every gapRecovery consecutive successes halve the gap again.
//
// Other hosts are not affected, and results are never altered — a throttled
// host is only probed more slowly.
const (
	maxPause       = 30 * time.Second
	defaultPause   = time.Second
	minGap         = 100 * time.Millisecond
	maxGap         = 5 * time.Second
	gapRecovery    = 4
	unlimitedStart = 64 // upper limit when -ch 0
)

type adaptState struct {
	mu         sync.Mutex
	limit      int
	slowStart  bool
	ok         int // successes since the last change
	pauseUntil time.Time
	gap        time.Duration // minimum time between request starts
	gapOK      int           // successes since the gap last changed
	next       time.Time     // earliest start of the next request
}

type adaptive struct {
	max   int
	hosts *lru.Cache[string, *adaptState]
}

type adaptKey struct{}

func newAdaptive(perHostLimit int) *adaptive {
	if perHostLimit <= 0 {
		perHostLimit = unlimitedStart
	}
	return &adaptive{max: perHostLimit, hosts: lru.New[string, *adaptState](100000)}
}

func (a *adaptive) state(host string) *adaptState {
	return a.hosts.Update(host, func(old *adaptState, found bool) *adaptState {
		if found {
			return old
		}
		return &adaptState{limit: 1, slowStart: true}
	})
}

// limit is the host's current concurrency limit.
func (a *adaptive) limit(host string) int {
	s := a.state(host)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limit
}

// wait blocks while the host is paused and reserves the host's next start
// slot, gap after the previous one.
func (a *adaptive) wait(ctx context.Context, s *adaptState) error {
	s.mu.Lock()
	now := time.Now()
	at := now
	if s.pauseUntil.After(at) {
		at = s.pauseUntil
	}
	if s.next.After(at) {
		at = s.next
	}
	s.next = at.Add(s.gap)
	d := at.Sub(now)
	s.mu.Unlock()
	if d <= 0 {
		return nil
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

// observe feeds one probe outcome back.
func (a *adaptive) observe(host string, r *probe.Response, f *probe.Failure) {
	s := a.state(host)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r != nil && (r.StatusCode == http.StatusTooManyRequests || r.StatusCode == http.StatusServiceUnavailable):
		s.decrease()
		s.gap = min(max(2*s.gap, minGap), maxGap)
		s.gapOK = 0
		if until := time.Now().Add(retryAfter(r.Header.Get("Retry-After"))); until.After(s.pauseUntil) {
			s.pauseUntil = until
			s.next = until // requests already reserved before the 429 wait again
		}
	case f != nil && (f.Class == probe.ClassConnTimeout || f.Class == probe.ClassTLSTimeout || f.Class == probe.ClassResponseTimout):
		s.decrease()
	case r != nil:
		s.ok++
		if s.slowStart || s.ok >= s.limit {
			s.limit = min(s.limit+1, a.max)
			s.ok = 0
		}
		if s.gap > 0 {
			if s.gapOK++; s.gapOK >= gapRecovery {
				s.gapOK = 0
				if s.gap /= 2; s.gap < minGap/4 {
					s.gap = 0
				}
			}
		}
	}
}

func (s *adaptState) decrease() {
	s.limit = max(1, s.limit/2)
	s.slowStart = false
	s.ok = 0
}

// retryAfter parses delta-seconds or an HTTP date, bounded to maxPause.
func retryAfter(v string) time.Duration {
	if v == "" {
		return defaultPause
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	} else {
		return defaultPause
	}
	return min(max(d, 0), maxPause)
}
