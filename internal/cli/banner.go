package cli

import (
	"io"
	"strings"
	"unicode/utf8"
)

const logo = `                __
    ____  __  __/ /_______
   / __ \/ / / / / ___/ _ \
  / /_/ / /_/ / (__  )  __/
 / .___/\__,_/_/____/\___/
/_/
`

// printBanner writes the startup banner. It goes to stderr only when stderr
// is a terminal and -silent is off, so pipelines and logs never see it.
func printBanner(w io.Writer, color bool) {
	bold, dim, reset := "\x1b[1;97m", "\x1b[2m", "\x1b[0m"
	if !color {
		bold, dim, reset = "", "", ""
	}
	lines := strings.Split(strings.TrimSuffix(logo, "\n"), "\n")
	width := 0
	for _, l := range lines {
		width = max(width, utf8.RuneCountInString(l))
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(bold + l + reset + "\n")
	}
	// The footer ends where the logo's widest line ends (spaces, not tabs:
	// tab stops differ between terminals).
	const footer = "thelabx.io"
	pad := max(0, width-utf8.RuneCountInString(footer))
	b.WriteString("\n" + strings.Repeat(" ", pad) + dim + footer + reset + "\n\n")
	_, _ = io.WriteString(w, b.String())
}
