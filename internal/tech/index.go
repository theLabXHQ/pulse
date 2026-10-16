package tech

// Pulse addition (not in upstream wappalyzergo): pattern indexes.
//
// Upstream walks every app for every input (the body, each script src, each
// meta tag, the header and cookie maps) and iterates each app's pattern maps,
// which costs more than the regexes themselves once the prefilter skips most
// of them. The index maps an input straight to the patterns that can match
// it: by header/cookie/meta name, or by the literals found in it (see
// prefilter.go). Per-app aggregation (any pattern matched, highest
// confidence, most specific version, implied apps) is unchanged.

import (
	"slices"
	"unsafe"
)

type patRef struct {
	seq int32 // build order: keeps one app's patterns contiguous and ordered
	app string
	fp  *CompiledFingerprint
	key string // header/cookie/meta name, for key-indexed parts
	p   *ParsedPattern
}

// litIndex selects patterns of one part by the literals present in the input.
type litIndex struct {
	refs   []patRef
	set    *literalSet
	byLit  [][]int32 // literal id -> indexes into refs
	always []int32   // refs without a literal set
}

func newLitIndex(refs []patRef) *litIndex {
	li := &litIndex{refs: refs}
	var lits []string
	for _, r := range refs {
		lits = append(lits, r.p.literals...)
	}
	li.set = newLiteralSet(lits)
	li.byLit = make([][]int32, len(li.set.lits))
	for i, r := range refs {
		if r.p.literals == nil {
			li.always = append(li.always, int32(i))
			continue
		}
		for _, l := range r.p.literals {
			id := li.set.ids[l]
			li.byLit[id] = append(li.byLit[id], int32(i))
		}
	}
	return li
}

// candidates returns, in build order, the patterns that may match data.
func (li *litIndex) candidates(data string) []patRef {
	lower, filter := lowerForFilter(data)
	if !filter {
		return li.refs
	}
	found := li.set.find(unsafe.Slice(unsafe.StringData(lower), len(lower)))
	var idx []int32
	seen := make(map[int32]struct{})
	add := func(i int32) {
		if _, dup := seen[i]; !dup {
			seen[i] = struct{}{}
			idx = append(idx, i)
		}
	}
	for id, ok := range found {
		if ok {
			for _, i := range li.byLit[id] {
				add(i)
			}
		}
	}
	for _, i := range li.always {
		add(i)
	}
	slices.Sort(idx)
	out := make([]patRef, len(idx))
	for k, i := range idx {
		out[k] = li.refs[i]
	}
	return out
}

type index struct {
	html, script           *litIndex
	headers, cookies, meta map[string][]patRef
}

// buildIndex must run after Apps is fully loaded.
func (f *CompiledFingerprints) buildIndex() {
	var seq int32
	ref := func(app string, fp *CompiledFingerprint, key string, p *ParsedPattern) patRef {
		seq++
		return patRef{seq: seq, app: app, fp: fp, key: key, p: p}
	}
	var html, script []patRef
	ix := &index{headers: map[string][]patRef{}, cookies: map[string][]patRef{}, meta: map[string][]patRef{}}
	for app, fp := range f.Apps {
		for _, p := range fp.html {
			html = append(html, ref(app, fp, "", p))
		}
		for _, p := range fp.scriptSrc {
			script = append(script, ref(app, fp, "", p))
		}
		for k, p := range fp.headers {
			ix.headers[k] = append(ix.headers[k], ref(app, fp, k, p))
		}
		for k, p := range fp.cookies {
			ix.cookies[k] = append(ix.cookies[k], ref(app, fp, k, p))
		}
		for k, ps := range fp.meta {
			for _, p := range ps {
				ix.meta[k] = append(ix.meta[k], ref(app, fp, k, p))
			}
		}
	}
	ix.html, ix.script = newLitIndex(html), newLitIndex(script)
	f.idx = ix
}

func (ix *index) byKey(part part) map[string][]patRef {
	switch part {
	case headersPart:
		return ix.headers
	case cookiesPart:
		return ix.cookies
	case metaPart:
		return ix.meta
	}
	return nil
}

// aggregate evaluates candidates (one app's patterns contiguous) and reports
// each matching app once, followed by the apps it implies.
func aggregate(cands []patRef, value func(patRef) string) []matchPartResult {
	var out []matchPartResult
	for i := 0; i < len(cands); {
		app, fp := cands[i].app, cands[i].fp
		var matched bool
		var version string
		var confidence int
		for ; i < len(cands) && cands[i].app == app; i++ {
			p := cands[i].p
			if p == nil {
				matched = true
				continue
			}
			valid, versionString := p.Evaluate(value(cands[i]))
			if !valid {
				continue
			}
			matched = true
			if p.Confidence > confidence {
				confidence = p.Confidence
			}
			if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
				version = versionString
			}
		}
		if !matched {
			continue
		}
		out = append(out, matchPartResult{application: app, version: version, confidence: confidence})
		for _, implies := range fp.implies {
			out = append(out, matchPartResult{application: implies, confidence: confidence})
		}
	}
	return out
}

// matchString matches data against the html or script-src patterns.
func (f *CompiledFingerprints) matchString(data string, part part) []matchPartResult {
	var li *litIndex
	switch part {
	case htmlPart:
		li = f.idx.html
	case scriptPart:
		li = f.idx.script
	default:
		return nil
	}
	return aggregate(li.candidates(data), func(patRef) string { return data })
}

// matchKeyValueString matches one name/value pair (e.g. a meta tag).
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part) []matchPartResult {
	return aggregate(f.idx.byKey(part)[key], func(patRef) string { return value })
}

// matchMapString matches a set of name/value pairs (headers, cookies). One
// app's patterns for different names are aggregated together.
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part) []matchPartResult {
	byKey := f.idx.byKey(part)
	var cands []patRef
	for k := range keyValue {
		cands = append(cands, byKey[k]...)
	}
	slices.SortFunc(cands, func(a, b patRef) int { return int(a.seq - b.seq) })
	return aggregate(cands, func(r patRef) string { return keyValue[r.key] })
}
