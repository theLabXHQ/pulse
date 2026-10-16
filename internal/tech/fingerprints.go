package tech

import (
	"fmt"
)

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cats        []int                             `json:"cats"`
	CSS         []string                          `json:"css"`
	Cookies     map[string]string                 `json:"cookies"`
	Dom         map[string]map[string]interface{} `json:"dom"`
	JS          map[string]string                 `json:"js"`
	Headers     map[string]string                 `json:"headers"`
	HTML        []string                          `json:"html"`
	Script      []string                          `json:"scripts"`
	ScriptSrc   []string                          `json:"scriptSrc"`
	Meta        map[string][]string               `json:"meta"`
	Implies     []string                          `json:"implies"`
	Description string                            `json:"description"`
	Website     string                            `json:"website"`
	CPE         string                            `json:"cpe"`
	Icon        string                            `json:"icon"`
}

// CompiledFingerprints contains a map of fingerprints for tech detection
type CompiledFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*CompiledFingerprint
	// idx maps inputs to the patterns that can match them; see index.go.
	idx *index
}

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	// cats contain categories that are implicit with this tech
	cats []int
	// implies contains technologies that are implicit with this tech
	implies []string
	// description contains fingerprint description
	description string
	// website contains a URL associated with the fingerprint
	website string
	// icon contains a Icon associated with the fingerprint
	icon string
	// cookies contains fingerprints for target cookies
	cookies map[string]*ParsedPattern
	// headers contains fingerprints for target headers
	headers map[string]*ParsedPattern
	// html contains fingerprints for the target HTML
	html []*ParsedPattern
	// script contains fingerprints for scripts
	script []*ParsedPattern
	// scriptSrc contains fingerprints for script srcs
	scriptSrc []*ParsedPattern
	// meta contains fingerprints for meta tags
	meta map[string][]*ParsedPattern
	// cpe contains the cpe for a fingerpritn
	cpe string
}

// AppInfo contains basic information about an App.
type AppInfo struct {
	Description string
	Website     string
	CPE         string
	Icon        string
	Categories  []string
}

// CatsInfo contains basic information about an App.
type CatsInfo struct {
	Cats []int
}

// part is the part of the fingerprint to match
type part int

// parts that can be matched
const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptPart
	metaPart
)

// compileFingerprint compiles the patterns Fingerprint uses. Pulse: js and
// dom patterns are not compiled; upstream compiles them (~5.5k regexes) but
// never matches them.
func compileFingerprint(fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		cats:        fingerprint.Cats,
		implies:     fingerprint.Implies,
		description: fingerprint.Description,
		website:     fingerprint.Website,
		icon:        fingerprint.Icon,
		cookies:     make(map[string]*ParsedPattern),
		headers:     make(map[string]*ParsedPattern),
		html:        make([]*ParsedPattern, 0, len(fingerprint.HTML)),
		script:      make([]*ParsedPattern, 0, len(fingerprint.Script)),
		scriptSrc:   make([]*ParsedPattern, 0, len(fingerprint.ScriptSrc)),
		meta:        make(map[string][]*ParsedPattern),
		cpe:         fingerprint.CPE,
	}

	for header, pattern := range fingerprint.Cookies {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.cookies[header] = fingerprint
	}

	for header, pattern := range fingerprint.Headers {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.headers[header] = fingerprint
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for _, pattern := range fingerprint.ScriptSrc {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.scriptSrc = append(compiled.scriptSrc, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*ParsedPattern

		for _, pattern := range patterns {
			fingerprint, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.meta[meta] = compiledList
	}
	return compiled
}

func FormatAppVersion(app, version string) string {
	if version == "" {
		return app
	}
	return fmt.Sprintf("%s:%s", app, version)
}

// GetFingerprints returns the fingerprint string from wappalyzer
func GetFingerprints() string {
	return fingerprints
}
