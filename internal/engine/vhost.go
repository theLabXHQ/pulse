package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/theLabXHQ/pulse/internal/extract"
	"github.com/theLabXHQ/pulse/internal/output"
	"github.com/theLabXHQ/pulse/internal/probe"
)

// pageSig is what -vhost compares between responses.
type pageSig struct {
	status int
	title  string
	length int
}

func sigOf(r *probe.Response) pageSig {
	ct := r.Header.Get("Content-Type")
	t := ""
	if extract.IsTitleCandidate(ct, r.Body) {
		t = extract.Title(r.Body, ct)
	}
	return pageSig{status: r.StatusCode, title: t, length: len(r.Body)}
}

// lengthDiffers ignores small changes (timestamps, tokens).
func lengthDiffers(a, b int) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d > max(64, max(a, b)/10)
}

func (s pageSig) differs(o pageSig) bool {
	return s.status != o.status || s.title != o.title || lengthDiffers(s.length, o.length)
}

// vhost reports whether the server routes by Host header: a request for a
// random name under the target host gets a different page. Comparing a
// single pair would call any word-count change a virtual host, so dynamic
// pages would always look like one; a difference is re-checked against a
// second request for the real host, and if the page changes by itself only
// status and title are compared.
func (e *Engine) vhost(ctx context.Context, res *output.Result, buf *bytes.Buffer) bool {
	orig := pageSig{status: res.StatusCode, title: res.Title, length: res.BodyBytes}
	var b [6]byte
	_, _ = rand.Read(b[:])
	random := "pulse-" + hex.EncodeToString(b[:]) + "." + res.Host

	fetch := func(ctx context.Context) (pageSig, bool) {
		if err := e.BeforeAttempt(ctx); err != nil {
			return pageSig{}, false
		}
		r, f := e.client.Fetch(ctx, res.URL, buf)
		if f != nil {
			return pageSig{}, false
		}
		return sigOf(r), true
	}
	other, ok := fetch(probe.WithHost(ctx, random))
	if !ok || !orig.differs(other) {
		return false
	}
	again, ok := fetch(ctx)
	if !ok || !orig.differs(again) {
		return true // the real host's page is stable; the random one differs
	}
	// The page changes by itself: lengths say nothing.
	if again.title != orig.title {
		return again.status != other.status
	}
	return again.status != other.status || again.title != other.title
}
