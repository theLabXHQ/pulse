package tech

// Pulse addition (not in upstream wappalyzergo): a literal prefilter.
//
// Every pattern is compiled case-insensitively and run over the whole body,
// so a body is scanned by hundreds of regexes even though almost none can
// match. For most patterns we can derive a set of literals such that every
// match contains at least one of them (one literal for "wp-content/", one per
// branch for "(?:grandnode|nopcommerce)"). If none of them occurs in the
// (lowercased) input, the regex cannot match and is skipped. For the HTML body
// all literals are found in a single Aho-Corasick pass; index.go then
// evaluates only the patterns those literals select.
//
// Soundness: (?i) folds ASCII letters only with themselves, except 'k' with
// U+212A KELVIN SIGN and 's' with U+017F LATIN SMALL LETTER LONG S.
// strings.ToLower maps U+212A to 'k', but U+017F is already lower case, so an
// input containing it bypasses the prefilter.

import (
	"regexp/syntax"
	"strings"
)

// minLiteral is the shortest literal worth filtering on; shorter ones occur
// in nearly every page.
const minLiteral = 3

// maxLiterals bounds the alternatives kept for one pattern.
const maxLiterals = 16

const longS = "\u017f"

// required returns an any-of literal set for re, or nil. Every element is at
// least minLiteral bytes long.
func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return single(longestASCIIRun(re.Rune))
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
	case syntax.OpAlternate:
		// A match takes one branch, so every branch needs a set.
		var out []string
		for _, sub := range re.Sub {
			set := required(sub)
			if set == nil {
				return nil
			}
			out = append(out, set...)
		}
		out = dedupe(out)
		if len(out) > maxLiterals {
			return nil
		}
		return out
	case syntax.OpConcat:
		// Every child is required; keep the most selective child set.
		// Consecutive children with finitely many spellings ("uk-" followed
		// by "container|section") are joined into one set first.
		var best []string
		consider := func(set []string) {
			if better(set, best) {
				best = set
			}
		}
		cur := []string{""}
		flush := func() {
			consider(atLeast(cur))
			cur = []string{""}
		}
		for _, sub := range re.Sub {
			if ex := exact(sub); ex != nil {
				if next := cross(cur, ex); next != nil {
					cur = next
				} else {
					flush() // too many spellings: keep what we have, restart
					cur = ex
				}
				continue
			}
			flush()
			consider(required(sub))
		}
		flush()
		return best
	}
	return nil
}

// exact returns every string re can match, lowercased, if there are at most
// maxLiterals of them and all are ASCII; otherwise nil.
func exact(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r >= 0x80 {
				return nil
			}
		}
		return []string{strings.ToLower(string(re.Rune))}
	case syntax.OpEmptyMatch:
		return []string{""}
	case syntax.OpQuest:
		ex := exact(re.Sub[0])
		if ex == nil {
			return nil
		}
		return dedupe(append([]string{""}, ex...))
	case syntax.OpCharClass:
		// Small ASCII classes such as ["'] or [-_]. Under (?i) letter classes
		// include non-ASCII folds (k, s) and are rejected here.
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi >= 0x80 || int(hi-lo)+1+len(out) > maxLiterals {
				return nil
			}
			for r := lo; r <= hi; r++ {
				out = append(out, strings.ToLower(string(r)))
			}
		}
		return dedupe(out)
	case syntax.OpCapture:
		return exact(re.Sub[0])
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			ex := exact(sub)
			if ex == nil {
				return nil
			}
			out = append(out, ex...)
		}
		out = dedupe(out)
		if len(out) > maxLiterals {
			return nil
		}
		return out
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			ex := exact(sub)
			if ex == nil {
				return nil
			}
			if out = cross(out, ex); out == nil {
				return nil
			}
		}
		return out
	}
	return nil
}

// cross returns every a+b, or nil if that exceeds maxLiterals.
func cross(as, bs []string) []string {
	if len(as)*len(bs) > maxLiterals {
		return nil
	}
	out := make([]string, 0, len(as)*len(bs))
	for _, a := range as {
		for _, b := range bs {
			out = append(out, a+b)
		}
	}
	return dedupe(out)
}

// atLeast returns set if every element is long enough to filter on.
func atLeast(set []string) []string {
	for _, s := range set {
		if len(s) < minLiteral {
			return nil
		}
	}
	return set
}

func single(lit string) []string {
	if len(lit) < minLiteral {
		return nil
	}
	return []string{lit}
}

// commonHTML holds markup found on nearly every page. A literal inside it
// filters almost nothing, whatever its length.
const commonHTML = `<!doctype html><html lang=""><head><meta charset="utf-8"><meta name="" content="" /><meta property=""><title></title>` +
	`<link rel="stylesheet" type="text/css" href=""><link rel='stylesheet' href=''><script type="text/javascript" src=""></script>` +
	`<script src='' async defer></script><body class=""><div class="" id="" style=""><div id=''><span class=''></span><a href="https://www.` +
	`" title="" target="_blank"></a><img src="http://" alt="" width="" height=""><input type="hidden" name="" value=""><form action="" method="post">` +
	`<ul><li><p><br/><table><tr><td><iframe src=""></iframe><button type="submit">.js.css.png.jpg.gif.svg.min.js.min.css?ver=`

// better prefers sets of rare literals, then sets whose shortest literal is
// longer, then smaller sets.
func better(a, b []string) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	if ra, rb := rare(a), rare(b); ra != rb {
		return ra
	}
	ma, mb := minLen(a), minLen(b)
	if ma != mb {
		return ma > mb
	}
	return len(a) < len(b)
}

func rare(set []string) bool {
	for _, s := range set {
		if strings.Contains(commonHTML, s) {
			return false
		}
	}
	return true
}

func minLen(set []string) int {
	m := len(set[0])
	for _, s := range set[1:] {
		m = min(m, len(s))
	}
	return m
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// longestASCIIRun returns the longest run of ASCII runes, lowercased. A
// non-ASCII rune may fold to other code points, so runs stop there.
func longestASCIIRun(rs []rune) string {
	best, start := "", 0
	for i := 0; i <= len(rs); i++ {
		if i < len(rs) && rs[i] < 0x80 {
			continue
		}
		if i-start > len(best) {
			best = strings.ToLower(string(rs[start:i]))
		}
		start = i + 1
	}
	return best
}

// lowerForFilter returns target lowercased, and false if the prefilter must
// not be used for it.
func lowerForFilter(target string) (string, bool) {
	lower := strings.ToLower(target)
	return lower, !strings.Contains(lower, longS)
}

// literalSet is an Aho-Corasick automaton over the body literals of all
// patterns, compiled to a DFA over byte classes.
type literalSet struct {
	class   [256]uint8
	classes int
	delta   []int32   // state*classes + class -> next state
	out     [][]int32 // state -> literal ids ending here (including via suffix links)
	lits    []string
	ids     map[string]int32
}

func newLiteralSet(lits []string) *literalSet {
	s := &literalSet{ids: make(map[string]int32)}
	for _, l := range lits {
		if _, ok := s.ids[l]; !ok {
			s.ids[l] = int32(len(s.lits))
			s.lits = append(s.lits, l)
		}
	}
	// Bytes that occur in no literal share class 0.
	for _, l := range s.lits {
		for i := 0; i < len(l); i++ {
			if s.class[l[i]] == 0 {
				s.classes++
				s.class[l[i]] = uint8(s.classes)
			}
		}
	}
	s.classes++
	k := s.classes

	// Trie.
	s.delta = make([]int32, k)
	s.out = [][]int32{nil}
	for id, l := range s.lits {
		st := int32(0)
		for i := 0; i < len(l); i++ {
			c := int(s.class[l[i]])
			nx := s.delta[int(st)*k+c]
			if nx == 0 {
				nx = int32(len(s.out))
				s.delta[int(st)*k+c] = nx
				s.delta = append(s.delta, make([]int32, k)...)
				s.out = append(s.out, nil)
			}
			st = nx
		}
		s.out[st] = append(s.out[st], int32(id))
	}

	// BFS: suffix links turn the trie into a DFA.
	fail := make([]int32, len(s.out))
	queue := make([]int32, 0, len(s.out))
	for c := 0; c < k; c++ {
		if nx := s.delta[c]; nx != 0 {
			queue = append(queue, nx)
		}
	}
	for len(queue) > 0 {
		st := queue[0]
		queue = queue[1:]
		s.out[st] = append(s.out[st], s.out[fail[st]]...)
		for c := 0; c < k; c++ {
			nx := s.delta[int(st)*k+c]
			if nx == 0 {
				s.delta[int(st)*k+c] = s.delta[int(fail[st])*k+c]
				continue
			}
			fail[nx] = s.delta[int(fail[st])*k+c]
			queue = append(queue, nx)
		}
	}
	return s
}

// find returns, per literal id, whether it occurs in text.
func (s *literalSet) find(text []byte) []bool {
	found := make([]bool, len(s.lits))
	k := s.classes
	st := int32(0)
	for _, b := range text {
		st = s.delta[int(st)*k+int(s.class[b])]
		for _, id := range s.out[st] {
			found[id] = true
		}
	}
	return found
}
