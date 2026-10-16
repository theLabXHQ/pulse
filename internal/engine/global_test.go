package engine

import (
	"context"
	"testing"
	"time"

	"github.com/theLabXHQ/pulse/internal/probe"
)

// feed sends one full window: timeoutShare of failures, the rest successes
// with the given connect time.
func feed(g *globalCtl, connectMS, timeoutShare float64) {
	n := g.window()
	for i := 0; i < n; i++ {
		if float64(i) < timeoutShare*float64(n) {
			g.observe(nil, &probe.Failure{Error: &probe.Error{Class: probe.ClassConnTimeout}})
		} else {
			g.observe(&probe.Response{Timing: probe.Timing{Connect: connectMS}}, nil)
		}
	}
}

func TestGlobalCtlBacksOffOnlyOnCongestion(t *testing.T) {
	g := newGlobalCtl(200, nil)
	feed(g, 10, 0) // baseline
	if g.limit != 200 {
		t.Fatalf("limit %d", g.limit)
	}
	feed(g, 12, 0.8) // dead hosts: many timeouts, normal latency
	if g.limit != 200 {
		t.Fatalf("dead hosts must not throttle: %d", g.limit)
	}
	feed(g, 40, 0.01) // slow far-away hosts, no timeouts
	if g.limit != 200 {
		t.Fatalf("latency alone must not throttle: %d", g.limit)
	}
	feed(g, 40, 0.3) // congestion: both signals
	if g.limit != 150 {
		t.Fatalf("congestion: want 150, got %d", g.limit)
	}
	for i := 0; i < 20; i++ {
		feed(g, 40, 0.3)
	}
	if g.limit != 50 {
		t.Fatalf("floor is a quarter of -t: got %d", g.limit)
	}
	for i := 0; i < 50; i++ {
		feed(g, 10, 0)
	}
	if g.limit != 200 {
		t.Fatalf("recovery: got %d", g.limit)
	}
}

func TestGlobalCtlAcquireRespectsLimitAndCancel(t *testing.T) {
	g := newGlobalCtl(4, nil)
	g.limit = 2
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := g.acquire(ctx); err != nil {
			t.Fatalf("slot %d must be free: %v", i, err)
		}
	}
	got := make(chan error, 1)
	cctx, cancel := context.WithCancel(ctx)
	go func() { got <- g.acquire(cctx) }()
	select {
	case <-got:
		t.Fatal("third acquire must block at the limit")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("a canceled acquire must fail")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel must unblock a waiting acquire")
	}
	g.release()
	if g.acquire(ctx) != nil {
		t.Fatal("a released slot must be reusable")
	}
}
