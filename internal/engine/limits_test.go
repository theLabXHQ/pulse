package engine

import (
	"context"
	"testing"
	"time"
)

func TestPacerSpacesEvents(t *testing.T) {
	p := newPacer(100) // 10ms interval
	start := time.Now()
	for i := 0; i < 11; i++ {
		if err := p.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 95*time.Millisecond || el > 400*time.Millisecond {
		t.Fatalf("11 events at 100/s took %v, want ~100ms", el)
	}
	var nilPacer *pacer
	if err := nilPacer.Wait(context.Background()); err != nil {
		t.Fatal("nil pacer must not block")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slow := newPacer(0.1)
	_ = slow.Wait(context.Background())
	if err := slow.Wait(ctx); err == nil {
		t.Fatal("canceled wait must return error")
	}
}

func TestHostLimiterParksAndHandsOver(t *testing.T) {
	h := newHostLimiter(1, 0)
	a := &task{hostKey: "x", line: 1}
	b := &task{hostKey: "x", line: 2}
	c := &task{hostKey: "y", line: 3}
	if !h.acquire(a) || h.acquire(b) || !h.acquire(c) {
		t.Fatal("expected a and c to run, b to park")
	}
	if next := h.release(a); next != b {
		t.Fatalf("release should hand over b, got %+v", next)
	}
	if next := h.release(b); next != nil {
		t.Fatal("nothing left for x")
	}
	if h.release(c) != nil || len(h.hosts) != 0 {
		t.Fatal("host state must be cleaned up")
	}
}

func TestTrackerWatermark(t *testing.T) {
	tr := newTracker(5)
	tr.start(5)
	tr.add(5)
	tr.add(5)
	tr.dispatched(5)
	tr.start(6) // empty line: no tasks
	tr.dispatched(6)
	tr.start(7)
	tr.add(7)
	tr.dispatched(7)
	if tr.watermark() != 5 {
		t.Fatal("line 5 incomplete")
	}
	tr.done(7)
	if tr.watermark() != 5 {
		t.Fatal("out-of-order completion must not advance past 5")
	}
	tr.done(5)
	tr.done(5)
	if got := tr.watermark(); got != 8 {
		t.Fatalf("watermark %d, want 8", got)
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	p := t.TempDir() + "/r.json"
	if cp, err := LoadCheckpoint(p); err != nil || cp.NextLine != 0 {
		t.Fatal("missing file must load as zero")
	}
	if err := SaveCheckpoint(p, Checkpoint{NextLine: 42}); err != nil {
		t.Fatal(err)
	}
	cp, err := LoadCheckpoint(p)
	if err != nil || cp.NextLine != 42 {
		t.Fatalf("got %+v %v", cp, err)
	}
}
