package extract

import (
	"net/http"
	"sort"
	"sync"

	wappalyzer "github.com/theLabXHQ/pulse/internal/tech"
)

// TechDetector wraps the Wappalyzer fingerprint set (internal/tech). It is
// loaded lazily because indexing the fingerprints costs ~150ms and ~27MB of
// heap, which only -tech-detect runs should pay.
type TechDetector struct {
	once sync.Once
	w    *wappalyzer.Wappalyze
	err  error
}

// Detect returns the sorted technology names matched by headers and body.
func (t *TechDetector) Detect(h http.Header, body []byte) ([]string, error) {
	t.once.Do(func() { t.w, t.err = wappalyzer.New() })
	if t.err != nil {
		return nil, t.err
	}
	m := t.w.Fingerprint(h, body)
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
