package engine

import (
	"net/http"
	"testing"
	"time"

	"github.com/theLabXHQ/pulse/internal/probe"
)

func TestRetryAfter(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"":        defaultPause,
		"2":       2 * time.Second,
		"0":       0,
		"86400":   maxPause,
		"garbage": defaultPause,
		"-5":      defaultPause,
	} {
		if got := retryAfter(v); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", v, got, want)
		}
	}
	if d := retryAfter(time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)); d < time.Second || d > 3*time.Second {
		t.Errorf("HTTP date: %v", d)
	}
}

func TestAdaptiveAIMD(t *testing.T) {
	a := newAdaptive(8)
	ok := &probe.Response{StatusCode: 200, Header: http.Header{}}
	if a.limit("h") != 1 {
		t.Fatal("slow start begins at 1")
	}
	for i := 0; i < 5; i++ {
		a.observe("h", ok, nil)
	}
	if a.limit("h") != 6 {
		t.Fatalf("slow start: +1 per success, got %d", a.limit("h"))
	}
	a.observe("h", &probe.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"0"}}}, nil)
	if l := a.limit("h"); l != 3 {
		t.Fatalf("429 halves: got %d", l)
	}
	for i := 0; i < 3; i++ {
		a.observe("h", ok, nil)
	}
	if l := a.limit("h"); l != 4 {
		t.Fatalf("after slow start: +1 per window of successes, got %d", l)
	}
	a.observe("h", nil, &probe.Failure{Error: &probe.Error{Class: probe.ClassResponseTimout}})
	if l := a.limit("h"); l != 2 {
		t.Fatalf("timeout halves: got %d", l)
	}
	a.observe("h", nil, &probe.Failure{Error: &probe.Error{Class: probe.ClassConnRefused}})
	if l := a.limit("h"); l != 2 {
		t.Fatalf("refused is not congestion: got %d", l)
	}
	if a.limit("other") != 1 {
		t.Fatal("hosts are independent")
	}
}

// A shrinking limit must not strand parked tasks.
func TestHostLimiterShrinkDoesNotStrand(t *testing.T) {
	limit := 3
	h := newHostLimiter(3, 0)
	h.limitFor = func(string) int { return limit }
	tasks := make([]*task, 6)
	running := 0
	for i := range tasks {
		tasks[i] = &task{hostKey: "h"}
		if h.acquire(tasks[i]) {
			running++
		}
	}
	if running != 3 {
		t.Fatalf("running %d", running)
	}
	limit = 1 // the host pushed back
	done := 0
	queue := []*task{tasks[0], tasks[1], tasks[2]}
	for len(queue) > 0 {
		t0 := queue[0]
		queue = queue[1:]
		done++
		if next := h.release(t0); next != nil {
			queue = append(queue, next)
		}
	}
	if done != 6 {
		t.Fatalf("only %d of 6 tasks ran", done)
	}
}
