package cli

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// listFlag is a repeatable string flag; commaSplit also splits on commas.
type listFlag struct {
	vals       *[]string
	commaSplit bool
}

func (l listFlag) String() string {
	if l.vals == nil {
		return ""
	}
	return strings.Join(*l.vals, ",")
}

func (l listFlag) Set(s string) error {
	if !l.commaSplit {
		*l.vals = append(*l.vals, s)
		return nil
	}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l.vals = append(*l.vals, p)
		}
	}
	return nil
}

// secondsFlag accepts integer seconds ("10") or a Go duration ("1500ms").
type secondsFlag struct{ d *time.Duration }

func (s secondsFlag) String() string {
	if s.d == nil {
		return ""
	}
	return s.d.String()
}

func (s secondsFlag) Set(v string) error {
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		*s.d = time.Duration(n * float64(time.Second))
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("expected seconds or duration, got %q", v)
	}
	*s.d = d
	return nil
}

// sizeFlag accepts byte counts with optional k/m/g suffix (binary units).
type sizeFlag struct{ n *int64 }

func (s sizeFlag) String() string {
	if s.n == nil {
		return ""
	}
	return strconv.FormatInt(*s.n, 10)
}

func (s sizeFlag) Set(v string) error {
	v = strings.ToLower(strings.TrimSpace(v))
	mult := int64(1)
	for suf, m := range map[string]int64{"kb": 1 << 10, "k": 1 << 10, "mb": 1 << 20, "m": 1 << 20, "gb": 1 << 30, "g": 1 << 30} {
		if strings.HasSuffix(v, suf) {
			v, mult = strings.TrimSuffix(v, suf), m
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid size %q", v)
	}
	*s.n = n * mult
	return nil
}

// flagDoc collects help text grouped by topic.
type flagDoc struct {
	names string // "-sc, -status-code"
	typ   string // value placeholder ("string", "int", ...); "" for switches
	usage string
	def   string
}

type group struct {
	title string
	flags []flagDoc
}

type registry struct {
	fs     *flag.FlagSet
	groups []*group
}

func (r *registry) group(title string) *group {
	g := &group{title: title}
	r.groups = append(r.groups, g)
	return g
}

func (g *group) add(names, typ, usage, def string) {
	g.flags = append(g.flags, flagDoc{names, typ, usage, def})
}

func (r *registry) boolVar(g *group, p *bool, usage string, names ...string) {
	for _, n := range names {
		r.fs.BoolVar(p, n, *p, usage)
	}
	g.add(dashed(names), "", usage, "")
}

func (r *registry) durationVar(g *group, p *time.Duration, usage string, names ...string) {
	r.varFlag(g, secondsFlag{p}, "duration", usage, "", names...)
}

// compatVar registers common flags that Pulse accepts but that change
// nothing (its behaviour is already what they ask for); they stay out of
// the help.
func (r *registry) compatVar(p *bool, names ...string) {
	for _, n := range names {
		r.fs.BoolVar(p, n, false, "")
	}
}

func (r *registry) stringVar(g *group, p *string, usage string, names ...string) {
	for _, n := range names {
		r.fs.StringVar(p, n, *p, usage)
	}
	g.add(dashed(names), "string", usage, *p)
}

func (r *registry) intVar(g *group, p *int, usage string, names ...string) {
	for _, n := range names {
		r.fs.IntVar(p, n, *p, usage)
	}
	g.add(dashed(names), "int", usage, strconv.Itoa(*p))
}

func (r *registry) floatVar(g *group, p *float64, usage string, names ...string) {
	for _, n := range names {
		r.fs.Float64Var(p, n, *p, usage)
	}
	g.add(dashed(names), "float", usage, strconv.FormatFloat(*p, 'f', -1, 64))
}

func (r *registry) varFlag(g *group, v flag.Value, typ, usage, def string, names ...string) {
	for _, n := range names {
		r.fs.Var(v, n, usage)
	}
	g.add(dashed(names), typ, usage, def)
}

func dashed(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "-" + n
	}
	return strings.Join(out, ", ")
}

// optIntFlag is an int flag whose value is optional, like -bp:
// "-bp" sets def, "-bp=300" sets 300. (A space-separated value cannot be
// optional with the flag package; "-bp 300" is reported as a stray
// argument with a hint.)
type optIntFlag struct {
	n   *int
	def int
}

func (f optIntFlag) String() string {
	if f.n == nil || *f.n == 0 {
		return ""
	}
	return strconv.Itoa(*f.n)
}

func (f optIntFlag) Set(v string) error {
	if v == "true" {
		*f.n = f.def
		return nil
	}
	if v == "false" {
		*f.n = 0
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fmt.Errorf("expected a non-negative number, got %q", v)
	}
	*f.n = n
	return nil
}

func (f optIntFlag) IsBoolFlag() bool { return true }

// impersonateFlag is -tls-impersonate / -tlsi. There is one profile
// (Chrome), so it is a switch that also accepts "=chrome".
type impersonateFlag struct{ on *bool }

func (f impersonateFlag) String() string {
	if f.on != nil && *f.on {
		return "chrome"
	}
	return ""
}

func (f impersonateFlag) Set(v string) error {
	switch strings.ToLower(v) {
	case "true", "chrome":
		*f.on = true
	case "false", "":
		*f.on = false
	default:
		return fmt.Errorf("only the chrome profile is supported, got %q", v)
	}
	return nil
}

func (f impersonateFlag) IsBoolFlag() bool { return true }
