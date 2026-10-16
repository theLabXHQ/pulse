package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/theLabXHQ/pulse/internal/version"
)

// helpRequest is returned by parse for -h (short help) and -hh (every
// flag); Main prints it to stdout so that "pulse -h | less" works. It
// matches flag.ErrHelp with errors.Is.
type helpRequest struct {
	full bool
	r    *registry
}

func (h *helpRequest) Error() string { return "help requested" }

func (h *helpRequest) Is(target error) bool { return target == flag.ErrHelp }

// helpStyle colors the help on a terminal: headings bold, flag names
// cyan, defaults and hints dim.
type helpStyle struct{ bold, flag, dim, reset string }

func newHelpStyle(color bool) helpStyle {
	if !color {
		return helpStyle{}
	}
	return helpStyle{bold: "\x1b[1m", flag: "\x1b[36m", dim: "\x1b[2m", reset: "\x1b[0m"}
}

func (s helpStyle) heading(w io.Writer, title string) {
	fmt.Fprintf(w, "\n%s%s%s\n", s.bold, title, s.reset)
}

// helpRow is one line of the short help: flag names (each must exist) and
// a description; an empty description uses the flag's own usage text.
type helpRow struct {
	names []string
	desc  string
}

// helpGrid lists output fields three to a line: they are many and their
// descriptions short.
type helpGrid [][2]string

type helpSection struct {
	title string
	rows  []helpRow
	grid  helpGrid
	note  string
}

var shortHelp = []helpSection{
	{title: "TARGETS", rows: []helpRow{
		{[]string{"u"}, "target(s) to probe (repeatable, comma separated)"},
		{[]string{"l"}, "file with targets, one per line; '-' for stdin"},
		{[]string{"p"}, "ports, e.g. 80,443,8000-8010,https:8443"},
		{[]string{"path"}, "path(s) to probe: comma list or file"},
	}},
	{title: "SHOW", note: "fields in text output; JSON (-j) always has them all", grid: helpGrid{
		{"sc", "status code"}, {"title", "page title"}, {"server", "Server header"},
		{"td", "technologies"}, {"cl", "content length"}, {"ct", "content type"},
		{"ip", "connected IP"}, {"cdn", "CDN/WAF/cloud"}, {"location", "redirect target"},
		{"tls", "TLS version"}, {"hv", "HTTP version"}, {"rt", "response time"},
	}, rows: []helpRow{
		{[]string{"probe"}, "also show failed targets, with their error class"},
	}},
	{title: "MATCH / FILTER", rows: []helpRow{
		{[]string{"mc", "fc"}, "status codes, e.g. 200,301-303"},
		{[]string{"ms", "fs"}, "string in headers or body"},
		{[]string{"mdc", "fdc"}, `DSL, e.g. 'status_code == 200 && contains(body, "admin")'`},
	}},
	{title: "REQUEST", rows: []helpRow{
		{[]string{"fr"}, "follow redirects"},
		{[]string{"H"}, "custom header 'Name: value' (repeatable)"},
		{[]string{"x"}, "request method(s)"},
		{[]string{"r"}, "DNS resolvers (default: system, then 1.1.1.1/8.8.8.8)"},
	}},
	{title: "SPEED", rows: []helpRow{
		{[]string{"t"}, "concurrent probes"},
		{[]string{"rl"}, "requests per second, all hosts; 0 = unlimited"},
		{[]string{"ch"}, "concurrent probes per host; 0 = unlimited"},
		{[]string{"timeout"}, "per attempt"},
		{[]string{"adaptive"}, "back off per host on 429/503/timeouts"},
	}},
	{title: "OUTPUT", rows: []helpRow{
		{[]string{"j"}, "JSON Lines (schema " + version.SchemaVersion + ")"},
		{[]string{"o"}, "also write results to this file"},
		{[]string{"csv"}, "CSV"},
		{[]string{"silent"}, "results only: no banner, no summary"},
		{[]string{"resume"}, "save progress to a file and continue from it"},
	}},
}

var helpExamples = []string{
	"cat hosts.txt | pulse -sc -title -td",
	"pulse -l hosts.txt -p 80,443,8080-8090 -j -o results.jsonl",
	"pulse -l hosts.txt -path /admin,/login -mc 200,401 -ch 2 -rl 50",
}

// defaultOf returns a flag's default for the help, or "" when it has none
// worth showing.
func (r *registry) defaultOf(name string) string {
	f := r.fs.Lookup(name)
	if f == nil {
		return ""
	}
	switch d := f.DefValue; d {
	case "", "0", "false", "[]":
		return ""
	default:
		return d
	}
}

func (r *registry) shortUsage(w io.Writer, color bool) {
	s := newHelpStyle(color)
	fmt.Fprintf(w, "%spulse%s %s· fast HTTP probing for reconnaissance · %s · thelabx.io%s\n",
		s.bold, s.reset, s.dim, version.Version, s.reset)
	s.heading(w, "USAGE")
	fmt.Fprintf(w, "  pulse [flags] [-u target | -l file | < stdin]\n")
	for _, sec := range shortHelp {
		s.heading(w, sec.title)
		if sec.note != "" {
			fmt.Fprintf(w, "  %s%s%s\n", s.dim, sec.note, s.reset)
		}
		for i := 0; i < len(sec.grid); i += 3 {
			b := "  "
			for _, cell := range sec.grid[i:min(i+3, len(sec.grid))] {
				name := "-" + cell[0]
				b += s.flag + name + s.reset + strings.Repeat(" ", max(1, 10-len(name))) +
					cell[1] + strings.Repeat(" ", max(1, 16-len(cell[1])))
			}
			fmt.Fprintln(w, strings.TrimRight(b, " "))
		}
		for _, row := range sec.rows {
			names := make([]string, len(row.names))
			for i, n := range row.names {
				names[i] = "-" + n
			}
			label := strings.Join(names, " / ")
			colored := s.flag + strings.Join(names, s.reset+" / "+s.flag) + s.reset
			def := ""
			if d := r.defaultOf(row.names[0]); d != "" {
				def = " " + s.dim + "(default " + d + ")" + s.reset
			}
			fmt.Fprintf(w, "  %s%s%s%s\n", colored, strings.Repeat(" ", max(1, 13-len(label))), row.desc, def)
		}
	}
	s.heading(w, "EXAMPLES")
	for _, e := range helpExamples {
		fmt.Fprintf(w, "  %s$%s %s\n", s.dim, s.reset, e)
	}
	n := 0
	for _, g := range r.groups {
		n += len(g.flags)
	}
	fmt.Fprintf(w, "\n%sAll %d flags: %s%s-hh%s\n",
		s.dim, n, s.reset, s.flag, s.reset)
}

// usage prints every flag, grouped (-hh).
func (r *registry) usage(w io.Writer, color bool) {
	s := newHelpStyle(color)
	fmt.Fprintf(w, "%spulse%s %s· fast HTTP probing for reconnaissance · %s · thelabx.io%s\n",
		s.bold, s.reset, s.dim, version.Version, s.reset)
	s.heading(w, "USAGE")
	fmt.Fprintf(w, "  pulse [flags] [-u target | -l file | < stdin]\n")
	for _, g := range r.groups {
		s.heading(w, strings.ToUpper(g.title))
		for _, f := range g.flags {
			plain := "  " + f.names
			label := s.flag + strings.ReplaceAll(f.names, ", ", s.reset+", "+s.flag) + s.reset
			if f.typ != "" {
				plain += " " + f.typ
				label += " " + s.dim + f.typ + s.reset
			}
			pad := max(1, 36-len(plain))
			def := ""
			if f.def != "" && f.def != "0" && f.def != "false" {
				def = " " + s.dim + "(default " + f.def + ")" + s.reset
			}
			fmt.Fprintf(w, "  %s%s%s%s\n", label, strings.Repeat(" ", pad), f.usage, def)
		}
	}
	s.heading(w, "EXAMPLES")
	for _, e := range helpExamples {
		fmt.Fprintf(w, "  %s$%s %s\n", s.dim, s.reset, e)
	}
}
