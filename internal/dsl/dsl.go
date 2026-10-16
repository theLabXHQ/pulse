// Package dsl is a small expression language for -mdc/-fdc, for
// expressions like:
//
//	status_code == 200 && contains(body, "admin")
//	len(title) > 0 && !contains(to_lower(webserver), "cloudflare")
//	regex("wp-(content|includes)", body) || contains_any(tech, "WordPress", "Drupal")
//
// Values are strings, numbers (float64), booleans and string lists. A list
// compared with == or passed to contains matches if any element does.
// Expressions are parsed once and evaluated without reflection or I/O.
package dsl

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Vars supplies variable values during evaluation. Unknown names are an
// error at evaluation time (they are usually typos).
type Vars func(name string) (any, bool)

// Expr is a compiled expression; it is safe for concurrent use.
type Expr struct {
	src  string
	root node
}

func (e *Expr) String() string { return e.src }

// Compile parses src.
func Compile(src string) (*Expr, error) {
	p := &parser{lex: lexer{src: src}}
	p.next()
	n, err := p.expr(0)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", src, err)
	}
	if p.tok.kind != tEOF {
		return nil, fmt.Errorf("%q: unexpected %s at offset %d", src, p.tok, p.tok.pos)
	}
	return &Expr{src: src, root: n}, nil
}

// Eval evaluates e to a boolean.
func (e *Expr) Eval(vars Vars) (bool, error) {
	v, err := e.root.eval(vars)
	if err != nil {
		return false, err
	}
	return truthy(v), nil
}

// ---- lexer ----

type tokKind int

const (
	tEOF tokKind = iota
	tNum
	tStr
	tIdent
	tOp
	tLParen
	tRParen
	tComma
)

type token struct {
	kind tokKind
	text string
	num  float64
	pos  int
}

func (t token) String() string {
	if t.kind == tEOF {
		return "end of expression"
	}
	return strconv.Quote(t.text)
}

type lexer struct {
	src string
	pos int
}

func (l *lexer) next() (token, error) {
	for l.pos < len(l.src) && unicode.IsSpace(rune(l.src[l.pos])) {
		l.pos++
	}
	start := l.pos
	if l.pos >= len(l.src) {
		return token{kind: tEOF, pos: start}, nil
	}
	c := l.src[l.pos]
	switch {
	case c == '(':
		l.pos++
		return token{kind: tLParen, text: "(", pos: start}, nil
	case c == ')':
		l.pos++
		return token{kind: tRParen, text: ")", pos: start}, nil
	case c == ',':
		l.pos++
		return token{kind: tComma, text: ",", pos: start}, nil
	case c == '"' || c == '\'':
		quote := c
		l.pos++
		var b strings.Builder
		for l.pos < len(l.src) && l.src[l.pos] != quote {
			if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
				l.pos++
				switch l.src[l.pos] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(l.src[l.pos])
				}
			} else {
				b.WriteByte(l.src[l.pos])
			}
			l.pos++
		}
		if l.pos >= len(l.src) {
			return token{}, fmt.Errorf("unterminated string at offset %d", start)
		}
		l.pos++
		return token{kind: tStr, text: b.String(), pos: start}, nil
	case c >= '0' && c <= '9':
		for l.pos < len(l.src) && (l.src[l.pos] >= '0' && l.src[l.pos] <= '9' || l.src[l.pos] == '.') {
			l.pos++
		}
		n, err := strconv.ParseFloat(l.src[start:l.pos], 64)
		if err != nil {
			return token{}, fmt.Errorf("bad number %q", l.src[start:l.pos])
		}
		return token{kind: tNum, text: l.src[start:l.pos], num: n, pos: start}, nil
	case c == '_' || unicode.IsLetter(rune(c)):
		for l.pos < len(l.src) && (l.src[l.pos] == '_' || l.src[l.pos] == '.' || unicode.IsLetter(rune(l.src[l.pos])) || unicode.IsDigit(rune(l.src[l.pos]))) {
			l.pos++
		}
		return token{kind: tIdent, text: l.src[start:l.pos], pos: start}, nil
	}
	for _, op := range []string{"==", "!=", "<=", ">=", "&&", "||", "<", ">", "!"} {
		if strings.HasPrefix(l.src[l.pos:], op) {
			l.pos += len(op)
			return token{kind: tOp, text: op, pos: start}, nil
		}
	}
	return token{}, fmt.Errorf("unexpected %q at offset %d", c, start)
}

// ---- parser (precedence climbing) ----

type parser struct {
	lex lexer
	tok token
	err error
}

func (p *parser) next() {
	if p.err != nil {
		return
	}
	p.tok, p.err = p.lex.next()
}

var precedence = map[string]int{"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 4, "<=": 4, ">": 4, ">=": 4}

func (p *parser) expr(minPrec int) (node, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.err == nil && p.tok.kind == tOp {
		prec, ok := precedence[p.tok.text]
		if !ok || prec <= minPrec {
			break
		}
		op := p.tok.text
		p.next()
		right, err := p.expr(prec)
		if err != nil {
			return nil, err
		}
		left = &binary{op: op, l: left, r: right}
	}
	return left, p.err
}

func (p *parser) unary() (node, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.tok.kind == tOp && p.tok.text == "!" {
		p.next()
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &not{n}, nil
	}
	return p.primary()
}

func (p *parser) primary() (node, error) {
	t := p.tok
	switch t.kind {
	case tNum:
		p.next()
		return literal{t.num}, p.err
	case tStr:
		p.next()
		return literal{t.text}, p.err
	case tLParen:
		p.next()
		n, err := p.expr(0)
		if err != nil {
			return nil, err
		}
		if p.tok.kind != tRParen {
			return nil, fmt.Errorf("expected ) at offset %d", p.tok.pos)
		}
		p.next()
		return n, p.err
	case tIdent:
		p.next()
		switch t.text {
		case "true":
			return literal{true}, p.err
		case "false":
			return literal{false}, p.err
		}
		if p.tok.kind != tLParen {
			return variable(t.text), p.err
		}
		fn, ok := functions[t.text]
		if !ok {
			return nil, fmt.Errorf("unknown function %s (known: %s)", t.text, functionNames())
		}
		p.next()
		var args []node
		for p.tok.kind != tRParen {
			a, err := p.expr(0)
			if err != nil {
				return nil, err
			}
			args = append(args, a)
			if p.tok.kind == tComma {
				p.next()
				continue
			}
			if p.tok.kind != tRParen {
				return nil, fmt.Errorf("expected , or ) at offset %d", p.tok.pos)
			}
		}
		p.next()
		if len(args) < fn.minArgs || (fn.maxArgs >= 0 && len(args) > fn.maxArgs) {
			return nil, fmt.Errorf("%s: wrong number of arguments (%d)", t.text, len(args))
		}
		c := &call{name: t.text, fn: fn, args: args}
		if t.text == "regex" { // compile constant patterns once
			if lit, ok := args[0].(literal); ok {
				s, _ := lit.v.(string)
				re, err := regexp.Compile(s)
				if err != nil {
					return nil, fmt.Errorf("regex: %w", err)
				}
				c.re = re
			}
		}
		return c, p.err
	}
	if p.err != nil {
		return nil, p.err
	}
	return nil, fmt.Errorf("unexpected %s at offset %d", t, t.pos)
}

// ---- evaluation ----

type node interface {
	eval(Vars) (any, error)
}

type literal struct{ v any }

func (l literal) eval(Vars) (any, error) { return l.v, nil }

type variable string

func (v variable) eval(vars Vars) (any, error) {
	if x, ok := vars(string(v)); ok {
		return x, nil
	}
	return nil, fmt.Errorf("unknown variable %s", string(v))
}

type not struct{ n node }

func (n *not) eval(vars Vars) (any, error) {
	v, err := n.n.eval(vars)
	return !truthy(v), err
}

type binary struct {
	op   string
	l, r node
}

func (b *binary) eval(vars Vars) (any, error) {
	l, err := b.l.eval(vars)
	if err != nil {
		return nil, err
	}
	switch b.op { // short-circuit
	case "&&":
		if !truthy(l) {
			return false, nil
		}
		r, err := b.r.eval(vars)
		return truthy(r), err
	case "||":
		if truthy(l) {
			return true, nil
		}
		r, err := b.r.eval(vars)
		return truthy(r), err
	}
	r, err := b.r.eval(vars)
	if err != nil {
		return nil, err
	}
	switch b.op {
	case "==":
		return equal(l, r), nil
	case "!=":
		return !equal(l, r), nil
	}
	ln, lok := number(l)
	rn, rok := number(r)
	if !lok || !rok {
		return nil, fmt.Errorf("%s needs numbers, got %v and %v", b.op, l, r)
	}
	switch b.op {
	case "<":
		return ln < rn, nil
	case "<=":
		return ln <= rn, nil
	case ">":
		return ln > rn, nil
	default:
		return ln >= rn, nil
	}
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []string:
		return len(x) > 0
	}
	return false
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return n, err == nil
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case []string:
		return strings.Join(x, ",")
	}
	return ""
}

func equal(a, b any) bool {
	if l, ok := a.([]string); ok {
		for _, s := range l {
			if equal(s, b) {
				return true
			}
		}
		return false
	}
	if l, ok := b.([]string); ok {
		return equal(l, a)
	}
	an, aok := a.(float64)
	bn, bok := b.(float64)
	switch {
	case aok && bok:
		return an == bn
	case aok || bok: // number vs string: compare numerically when possible
		x, ok1 := number(a)
		y, ok2 := number(b)
		return ok1 && ok2 && x == y
	}
	return str(a) == str(b)
}

// ---- functions ----

type function struct {
	minArgs, maxArgs int // maxArgs -1 = variadic
	f                func(args []any, re *regexp.Regexp) (any, error)
}

type call struct {
	name string
	fn   function
	args []node
	re   *regexp.Regexp
}

func (c *call) eval(vars Vars) (any, error) {
	args := make([]any, len(c.args))
	for i, a := range c.args {
		v, err := a.eval(vars)
		if err != nil {
			return nil, err
		}
		args[i] = v
	}
	return c.fn.f(args, c.re)
}

// haystacks returns the strings a value stands for (a list's elements).
func haystacks(v any) []string {
	if l, ok := v.([]string); ok {
		return l
	}
	return []string{str(v)}
}

func anyContains(v any, needle string) bool {
	for _, h := range haystacks(v) {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

var functions = map[string]function{
	"contains": {2, 2, func(a []any, _ *regexp.Regexp) (any, error) { return anyContains(a[0], str(a[1])), nil }},
	"contains_any": {2, -1, func(a []any, _ *regexp.Regexp) (any, error) {
		for _, n := range a[1:] {
			if anyContains(a[0], str(n)) {
				return true, nil
			}
		}
		return false, nil
	}},
	"contains_all": {2, -1, func(a []any, _ *regexp.Regexp) (any, error) {
		for _, n := range a[1:] {
			if !anyContains(a[0], str(n)) {
				return false, nil
			}
		}
		return true, nil
	}},
	"starts_with": {2, -1, func(a []any, _ *regexp.Regexp) (any, error) {
		for _, n := range a[1:] {
			if strings.HasPrefix(str(a[0]), str(n)) {
				return true, nil
			}
		}
		return false, nil
	}},
	"ends_with": {2, -1, func(a []any, _ *regexp.Regexp) (any, error) {
		for _, n := range a[1:] {
			if strings.HasSuffix(str(a[0]), str(n)) {
				return true, nil
			}
		}
		return false, nil
	}},
	"regex": {2, 2, func(a []any, re *regexp.Regexp) (any, error) {
		if re == nil {
			var err error
			if re, err = regexp.Compile(str(a[0])); err != nil {
				return nil, fmt.Errorf("regex: %w", err)
			}
		}
		for _, h := range haystacks(a[1]) {
			if re.MatchString(h) {
				return true, nil
			}
		}
		return false, nil
	}},
	"len": {1, 1, func(a []any, _ *regexp.Regexp) (any, error) {
		if l, ok := a[0].([]string); ok {
			return float64(len(l)), nil
		}
		return float64(len(str(a[0]))), nil
	}},
	"to_lower": {1, 1, func(a []any, _ *regexp.Regexp) (any, error) { return mapStr(a[0], strings.ToLower), nil }},
	"to_upper": {1, 1, func(a []any, _ *regexp.Regexp) (any, error) { return mapStr(a[0], strings.ToUpper), nil }},
	"trim":     {1, 1, func(a []any, _ *regexp.Regexp) (any, error) { return mapStr(a[0], strings.TrimSpace), nil }},
}

func init() {
	// alternative spellings
	functions["tolower"] = functions["to_lower"]
	functions["toupper"] = functions["to_upper"]
}

func mapStr(v any, f func(string) string) any {
	if l, ok := v.([]string); ok {
		out := make([]string, len(l))
		for i, s := range l {
			out[i] = f(s)
		}
		return out
	}
	return f(str(v))
}

func functionNames() string {
	var names []string
	for n := range functions {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// Variables returns the variable names e refers to, so callers can reject
// typos before evaluating anything.
func (e *Expr) Variables() []string {
	seen := map[string]bool{}
	var walk func(n node)
	walk = func(n node) {
		switch x := n.(type) {
		case variable:
			seen[string(x)] = true
		case *not:
			walk(x.n)
		case *binary:
			walk(x.l)
			walk(x.r)
		case *call:
			for _, a := range x.args {
				walk(a)
			}
		}
	}
	walk(e.root)
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
