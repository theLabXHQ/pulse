package engine

import (
	"bytes"
	"testing"
)

func TestTrackerIntervalsBoundMemory(t *testing.T) {
	tr := newTracker(0)
	tr.start(0) // a slow line that stays open
	tr.add(0)
	tr.dispatched(0)
	for i := int64(1); i <= 100000; i++ {
		tr.start(i)
		tr.dispatched(i) // no tasks: complete at once
	}
	if wm := tr.watermark(); wm != 0 {
		t.Fatalf("watermark %d, want 0 while line 0 is open", wm)
	}
	if len(tr.lines) != 1 || len(tr.ahead) != 1 {
		t.Fatalf("finished lines must collapse: %d map entries, %d intervals", len(tr.lines), len(tr.ahead))
	}
	tr.done(0)
	if wm := tr.watermark(); wm != 100001 {
		t.Fatalf("watermark %d, want 100001", wm)
	}
	// Out-of-order completion with gaps.
	tr2 := newTracker(0)
	for i := int64(0); i < 6; i++ {
		tr2.start(i)
		tr2.add(i)
		tr2.dispatched(i)
	}
	for _, i := range []int64{5, 3, 1, 4, 0} {
		tr2.done(i)
	}
	if wm := tr2.watermark(); wm != 2 {
		t.Fatalf("watermark %d, want 2 (line 2 open)", wm)
	}
	tr2.done(2)
	if wm := tr2.watermark(); wm != 6 || len(tr2.ahead) != 0 {
		t.Fatalf("watermark %d ahead %v", wm, tr2.ahead)
	}
}

func TestTrimBufDropsOversizedBuffers(t *testing.T) {
	small := bytes.NewBuffer(make([]byte, 0, 4<<10))
	if trimBuf(small) != small {
		t.Error("small buffer replaced")
	}
	big := bytes.NewBuffer(make([]byte, 0, maxKeptBuf+1))
	if got := trimBuf(big); got == big || got.Cap() != 0 {
		t.Errorf("oversized buffer kept (cap %d)", got.Cap())
	}
}
