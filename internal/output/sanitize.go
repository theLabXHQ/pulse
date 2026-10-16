package output

import (
	"fmt"
	"strings"
)

// clean makes server-controlled text safe for a terminal or spreadsheet:
// C0/C1 control characters and DEL (escape sequences, bell, OSC window-title
// changes) are shown as \xNN instead of being interpreted. JSON output
// escapes them already.
func clean(s string) string {
	if !hasControl(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if isControl(r) {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) }

func hasControl(s string) bool {
	for _, r := range s {
		if isControl(r) {
			return true
		}
	}
	return false
}
