package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Checkpoint is the on-disk resume state. NextLine is a low-watermark: every
// input line before it has been fully probed and written, so resuming from it
// never loses results (lines after it may be probed twice, never zero times).
type Checkpoint struct {
	Version  int       `json:"version"`
	NextLine int64     `json:"next_line"`
	SavedAt  time.Time `json:"saved_at"`
	Args     []string  `json:"args,omitempty"`
}

// LoadCheckpoint reads a checkpoint; a missing file yields NextLine 0.
func LoadCheckpoint(path string) (Checkpoint, error) {
	var cp Checkpoint
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cp, nil
	}
	if err != nil {
		return cp, err
	}
	if err := json.Unmarshal(data, &cp); err != nil {
		return cp, fmt.Errorf("corrupt resume file %s: %w", path, err)
	}
	if cp.Version != 1 || cp.NextLine < 0 {
		return cp, fmt.Errorf("unsupported resume file %s", path)
	}
	return cp, nil
}

// SaveCheckpoint writes atomically (temp file + rename).
func SaveCheckpoint(path string, cp Checkpoint) error {
	cp.Version = 1
	cp.SavedAt = time.Now().UTC()
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pulse-resume-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

type lineState struct {
	pending    int
	dispatched bool
}

// tracker computes the completion low-watermark over input lines. Lines are
// started in increasing order by the single dispatcher; tasks complete in any
// order. A task counts as complete once its result has been written (or it
// was filtered), see Engine.finish.
//
// Only lines still in progress live in the map (bounded by the in-flight
// limit). Lines that complete while an earlier one is still open are kept
// as merged intervals, so one slow line followed by millions of finished
// ones costs a few intervals, not one map entry per line.
type tracker struct {
	mu    sync.Mutex
	next  int64 // lowest line not yet complete
	lines map[int64]*lineState
	ahead []span // completed lines > next, sorted, non-adjacent
}

type span struct{ lo, hi int64 } // inclusive

func newTracker(start int64) *tracker {
	return &tracker{next: start, lines: make(map[int64]*lineState)}
}

func (t *tracker) start(line int64) {
	t.mu.Lock()
	t.lines[line] = &lineState{}
	t.mu.Unlock()
}

func (t *tracker) add(line int64) {
	t.mu.Lock()
	t.lines[line].pending++
	t.mu.Unlock()
}

func (t *tracker) dispatched(line int64) {
	t.mu.Lock()
	t.lines[line].dispatched = true
	t.settle(line)
	t.mu.Unlock()
}

func (t *tracker) done(line int64) {
	t.mu.Lock()
	t.lines[line].pending--
	t.settle(line)
	t.mu.Unlock()
}

// settle moves a completed line out of the map and advances the watermark.
func (t *tracker) settle(line int64) {
	ls := t.lines[line]
	if !ls.dispatched || ls.pending > 0 {
		return
	}
	delete(t.lines, line)
	t.markDone(line)
	for len(t.ahead) > 0 && t.ahead[0].lo == t.next {
		t.next = t.ahead[0].hi + 1
		t.ahead = t.ahead[1:]
	}
}

// markDone inserts line into ahead, merging neighbours.
func (t *tracker) markDone(line int64) {
	i := sort.Search(len(t.ahead), func(i int) bool { return t.ahead[i].hi >= line-1 })
	switch {
	case i < len(t.ahead) && t.ahead[i].lo <= line+1 && t.ahead[i].hi >= line-1:
		sp := &t.ahead[i]
		sp.lo, sp.hi = min(sp.lo, line), max(sp.hi, line)
		if i+1 < len(t.ahead) && t.ahead[i+1].lo == sp.hi+1 { // bridged a gap
			sp.hi = t.ahead[i+1].hi
			t.ahead = append(t.ahead[:i+1], t.ahead[i+2:]...)
		}
	default:
		t.ahead = append(t.ahead, span{})
		copy(t.ahead[i+1:], t.ahead[i:])
		t.ahead[i] = span{line, line}
	}
}

// watermark returns the first incomplete line.
func (t *tracker) watermark() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.next
}
