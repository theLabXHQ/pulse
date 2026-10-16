package output

import (
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/theLabXHQ/pulse/internal/probe"
)

func TestTerminalInjectionIsNeutralized(t *testing.T) {
	evil := "\x1b[31mRED\x1b[0m\x07bell\x1b]0;pwned\x07\u009b2J"
	r := &Result{URL: "http://x/", StatusCode: 200, Title: evil, WebServer: evil, Location: evil}
	for _, color := range []bool{false, true} {
		out := FormatText(r, TextFields{Title: true, WebServer: true, Location: true}, color)
		for _, c := range []string{cReset, cBold, cDim, cRed, cGreen, cYellow, cBlue, cMagenta, cCyan} {
			out = strings.ReplaceAll(out, c, "") // Pulse's own colors
		}
		if strings.ContainsAny(out, "\x1b\x07\u009b") {
			t.Fatalf("control characters reached the terminal: %q", out)
		}
		if !strings.Contains(out, `\x1b[31mRED`) {
			t.Fatalf("escaped form missing: %q", out)
		}
	}
	for _, f := range csvRecord(r) {
		if strings.ContainsAny(f, "\x1b\x07") {
			t.Fatalf("control characters in CSV: %q", f)
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A result counts as written only after a successful flush; if output
// fails, its OnWritten is never called (so -resume keeps the line open).
func TestOnWrittenOnlyAfterSuccessfulFlush(t *testing.T) {
	for _, c := range []struct {
		out  io.Writer
		want int64
	}{{io.Discard, 3}, {failWriter{}, 0}} {
		var done atomic.Int64
		w := New(Config{Format: FormatJSONL, Stdout: c.out}, 8)
		go func() {
			for i := 0; i < 3; i++ {
				w.In() <- &Result{URL: "http://x/", OnWritten: func() { done.Add(1) }}
			}
			close(w.In())
		}()
		_ = w.Run()
		if done.Load() != c.want {
			t.Errorf("%T: OnWritten called %d times, want %d", c.out, done.Load(), c.want)
		}
	}
}

// Without color the text line is the plain format: scripts that
// parse it must not notice the palette.
func TestPlainTextFormatUnchanged(t *testing.T) {
	r := &Result{URL: "https://a.test/", StatusCode: 301, Title: "Hi", WebServer: "nginx",
		Chain: []probe.Hop{{StatusCode: 301}, {StatusCode: 200}}, Tech: []string{"Nginx", "PHP"}}
	got := FormatText(r, TextFields{StatusCode: true, Title: true, WebServer: true, Tech: true}, false)
	if want := "https://a.test/ [301,200] [Hi] [nginx] [Nginx,PHP]"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	colored := FormatText(r, TextFields{StatusCode: true, Title: true, WebServer: true, Tech: true}, true)
	for _, c := range []string{cReset, cBold, cDim, cRed, cGreen, cYellow, cBlue, cMagenta, cCyan} {
		colored = strings.ReplaceAll(colored, c, "")
	}
	if colored != got {
		t.Fatalf("colored text differs beyond colors: %q", colored)
	}
}
