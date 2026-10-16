// Package match implements the matchers (-mc, -ms, -mr, ...) and
// filters (-fc, -fs, -fe, ...). A result is kept if it passes every
// configured matcher and no configured filter.
package match

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/theLabXHQ/pulse/internal/dsl"
)

// Input is the data matchers look at. Headers is the raw header block.
type Input struct {
	StatusCode    int
	ContentLength int64
	Lines, Words  int
	Headers       []byte
	Body          []byte
	CDNName       string  // provider, "" if none
	CDNType       string  // cdn, waf, cloud
	Seconds       float64 // total probe time
}

// Rules holds parsed matchers and filters.
type Rules struct {
	MatchCodes, FilterCodes     map[int]bool
	MatchLengths, FilterLengths map[int64]bool
	MatchLines, FilterLines     map[int]bool
	MatchWords, FilterWords     map[int]bool
	MatchStrings, FilterStrings [][]byte // lower-cased, case-insensitive
	MatchRegex, FilterRegex     []*regexp.Regexp
	MatchFavicon, FilterFavicon map[string]bool
	MatchCDN, FilterCDN         map[string]bool // provider names or kinds (cdn, waf, cloud)
	MatchDSL, FilterDSL         []*dsl.Expr     // -mdc/-fdc: keep if any -mdc holds and no -fdc does
	MatchTime, FilterTime       *TimeCond       // -mrt/-frt
}

// Empty reports whether no rule is configured.
func (r *Rules) Empty() bool {
	return len(r.MatchCodes)+len(r.FilterCodes)+len(r.MatchLengths)+len(r.FilterLengths)+
		len(r.MatchLines)+len(r.FilterLines)+len(r.MatchWords)+len(r.FilterWords)+
		len(r.MatchStrings)+len(r.FilterStrings)+len(r.MatchRegex)+len(r.FilterRegex)+
		len(r.MatchFavicon)+len(r.FilterFavicon)+len(r.MatchCDN)+len(r.FilterCDN)+
		len(r.MatchDSL)+len(r.FilterDSL) == 0 && r.MatchTime == nil && r.FilterTime == nil
}

// NeedsBody reports whether rules inspect headers/body content.
func (r *Rules) NeedsBody() bool {
	return len(r.MatchStrings)+len(r.FilterStrings)+len(r.MatchRegex)+len(r.FilterRegex) > 0
}

// HasCDNRules reports whether -mcdn/-fcdn are configured.
func (r *Rules) HasCDNRules() bool { return len(r.MatchCDN)+len(r.FilterCDN) > 0 }

// Keep evaluates the rules.
func (r *Rules) Keep(in Input) bool {
	if r.MatchTime != nil && !r.MatchTime.Holds(in.Seconds) {
		return false
	}
	if r.FilterTime != nil && r.FilterTime.Holds(in.Seconds) {
		return false
	}
	if len(r.MatchCDN) > 0 && !(r.MatchCDN[in.CDNName] || r.MatchCDN[in.CDNType]) {
		return false
	}
	if in.CDNName != "" && (r.FilterCDN[in.CDNName] || r.FilterCDN[in.CDNType]) {
		return false
	}
	if len(r.MatchCodes) > 0 && !r.MatchCodes[in.StatusCode] {
		return false
	}
	if r.FilterCodes[in.StatusCode] {
		return false
	}
	if len(r.MatchLengths) > 0 && !r.MatchLengths[in.ContentLength] {
		return false
	}
	if r.FilterLengths[in.ContentLength] {
		return false
	}
	if len(r.MatchLines) > 0 && !r.MatchLines[in.Lines] {
		return false
	}
	if r.FilterLines[in.Lines] {
		return false
	}
	if len(r.MatchWords) > 0 && !r.MatchWords[in.Words] {
		return false
	}
	if r.FilterWords[in.Words] {
		return false
	}
	if len(r.MatchStrings)+len(r.FilterStrings) > 0 {
		hl, bl := bytes.ToLower(in.Headers), bytes.ToLower(in.Body)
		contains := func(s []byte) bool { return bytes.Contains(hl, s) || bytes.Contains(bl, s) }
		if len(r.MatchStrings) > 0 && !anyOf(r.MatchStrings, contains) {
			return false
		}
		if anyOf(r.FilterStrings, contains) {
			return false
		}
	}
	for _, re := range r.MatchRegex {
		if !re.Match(in.Headers) && !re.Match(in.Body) {
			return false
		}
	}
	for _, re := range r.FilterRegex {
		if re.Match(in.Headers) || re.Match(in.Body) {
			return false
		}
	}
	return true
}

// HasDSL reports whether -mdc/-fdc are configured.
func (r *Rules) HasDSL() bool { return len(r.MatchDSL)+len(r.FilterDSL) > 0 }

// KeepDSL evaluates -mdc/-fdc. An expression that fails at run time (for
// example a regex error) counts as not holding.
func (r *Rules) KeepDSL(vars dsl.Vars) bool {
	holds := func(e *dsl.Expr) bool {
		ok, err := e.Eval(vars)
		return err == nil && ok
	}
	if len(r.MatchDSL) > 0 {
		any := false
		for _, e := range r.MatchDSL {
			if holds(e) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	for _, e := range r.FilterDSL {
		if holds(e) {
			return false
		}
	}
	return true
}

// HasFaviconRules reports whether favicon matchers/filters are configured.
func (r *Rules) HasFaviconRules() bool { return len(r.MatchFavicon)+len(r.FilterFavicon) > 0 }

// KeepFavicon evaluates only the favicon rules (-mfc/-ffc), which can run
// only after favicon enrichment.
func (r *Rules) KeepFavicon(mmh3 string) bool {
	if len(r.MatchFavicon) > 0 && !r.MatchFavicon[mmh3] {
		return false
	}
	return !r.FilterFavicon[mmh3]
}

func anyOf(items [][]byte, f func([]byte) bool) bool {
	for _, it := range items {
		if f(it) {
			return true
		}
	}
	return false
}

// ParseInts parses "200,301-303" into a set.
func ParseInts(s string) (map[int]bool, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	out := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a || b-a > 100000 {
				return nil, fmt.Errorf("invalid range %q", part)
			}
		}
		for i := a; i <= b; i++ {
			out[i] = true
		}
	}
	return out, nil
}

// ParseInt64s parses a list of lengths.
func ParseInt64s(s string) (map[int64]bool, error) {
	ints, err := ParseInts(s)
	if err != nil || ints == nil {
		return nil, err
	}
	out := make(map[int64]bool, len(ints))
	for k := range ints {
		out[int64(k)] = true
	}
	return out, nil
}

// ParseStrings splits a comma list into lower-cased byte patterns.
func ParseStrings(list []string) [][]byte {
	var out [][]byte
	for _, s := range list {
		if s != "" {
			out = append(out, []byte(strings.ToLower(s)))
		}
	}
	return out
}

// ParseRegexes compiles patterns.
func ParseRegexes(list []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, s := range list {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", s, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// ParseSet builds a string set.
func ParseSet(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, s := range list {
		out[strings.TrimSpace(s)] = true
	}
	return out
}

// TimeCond is a response-time condition such as "< 1" or ">= 0.5" (seconds).
type TimeCond struct {
	Op      string
	Seconds float64
}

// ParseTimeCond parses "<op> <seconds>"; op is <, <=, >, >=, == or =.
func ParseTimeCond(s string) (*TimeCond, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	for _, op := range []string{"<=", ">=", "==", "<", ">", "="} {
		if rest, ok := strings.CutPrefix(s, op); ok {
			v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(rest), "s"), 64)
			if err != nil || v < 0 {
				return nil, fmt.Errorf("bad seconds in %q", s)
			}
			return &TimeCond{Op: op, Seconds: v}, nil
		}
	}
	return nil, fmt.Errorf("expected an operator (< <= > >= ==) and seconds, got %q", s)
}

// Holds reports whether seconds satisfies the condition.
func (c *TimeCond) Holds(seconds float64) bool {
	switch c.Op {
	case "<":
		return seconds < c.Seconds
	case "<=":
		return seconds <= c.Seconds
	case ">":
		return seconds > c.Seconds
	case ">=":
		return seconds >= c.Seconds
	}
	return seconds == c.Seconds
}
