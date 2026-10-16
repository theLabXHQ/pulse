// Package logx is a minimal leveled logger for diagnostics on stderr.
// Results never go through it.
package logx

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// Logger writes "[LVL] message" lines. Safe for concurrent use.
type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	Verbose bool
	Silent  bool
	Color   bool
}

// New returns a logger writing to w.
func New(w io.Writer) *Logger { return &Logger{w: w} }

var labels = map[string]struct{ tag, color string }{
	"error":   {"ERR", "\x1b[31m"},
	"warn":    {"WRN", "\x1b[33m"},
	"info":    {"INF", "\x1b[34m"},
	"verbose": {"VER", "\x1b[90m"},
}

// Logf logs at level error, warn, info or verbose. Errors are always shown;
// warn/info are hidden by Silent; verbose needs Verbose.
func (l *Logger) Logf(level, format string, a ...any) {
	if l == nil {
		return
	}
	switch level {
	case "verbose":
		if !l.Verbose {
			return
		}
	case "warn", "info":
		if l.Silent && !l.Verbose { // -silent -v still shows why inputs were skipped
			return
		}
	}
	lb, ok := labels[level]
	if !ok {
		lb = labels["info"]
	}
	msg := fmt.Sprintf(format, a...)
	msg = strings.TrimRight(msg, "\n")
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Color {
		fmt.Fprintf(l.w, "[%s%s\x1b[0m] %s\n", lb.color, lb.tag, msg)
	} else {
		fmt.Fprintf(l.w, "[%s] %s\n", lb.tag, msg)
	}
}

// Printf writes a raw line (used for stats and the summary).
func (l *Logger) Printf(format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, format, a...)
}
