package tech

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
)

// ParsedPattern encapsulates a regular expression with
// additional metadata for confidence and version extraction.
type ParsedPattern struct {
	// Pulse: the regex is compiled on first use. With the prefilter most
	// patterns never run, and compiled programs dominate memory (the
	// {1,250} rewrite below expands every + and *).
	expr  string
	once  sync.Once
	regex *regexp.Regexp
	// literals: every match contains at least one of them (nil = no
	// constraint); see prefilter.go.
	literals []string

	Confidence int
	Version    string
	SkipRegex  bool
}

const (
	verCap1        = `(\d+(?:\.\d+)+)` // captures 1 set of digits '\d+' followed by one or more '\.\d+' patterns
	verCap1Fill    = "__verCap1__"
	verCap1Limited = `(\d{1,20}(?:\.\d{1,20}){1,20})`

	verCap2        = `((?:\d+\.)+\d+)` // captures 1 or more '\d+\.' patterns followed by 1 set of digits '\d+'
	verCap2Fill    = "__verCap2__"
	verCap2Limited = `((?:\d{1,20}\.){1,20}\d{1,20})`
)

// ParsePattern extracts information from a pattern, supporting both regex and simple patterns
func ParsePattern(pattern string) (*ParsedPattern, error) {
	parts := strings.Split(pattern, "\\;")
	p := &ParsedPattern{Confidence: 100}

	if parts[0] == "" {
		p.SkipRegex = true
	}
	for i, part := range parts {
		if i == 0 {
			if p.SkipRegex {
				continue
			}
			regexPattern := part

			// save version capture groups
			regexPattern = strings.ReplaceAll(regexPattern, verCap1, verCap1Fill)
			regexPattern = strings.ReplaceAll(regexPattern, verCap2, verCap2Fill)

			regexPattern = strings.ReplaceAll(regexPattern, "\\+", "__escapedPlus__")
			regexPattern = strings.ReplaceAll(regexPattern, "+", "{1,250}")
			regexPattern = strings.ReplaceAll(regexPattern, "*", "{0,250}")
			regexPattern = strings.ReplaceAll(regexPattern, "__escapedPlus__", "\\+")

			// restore version capture groups
			regexPattern = strings.ReplaceAll(regexPattern, verCap1Fill, verCap1Limited)
			regexPattern = strings.ReplaceAll(regexPattern, verCap2Fill, verCap2Limited)

			// Parse is where regexp.Compile can fail, so invalid patterns
			// are still rejected here, as upstream does.
			p.expr = "(?i)" + regexPattern
			re, err := syntax.Parse(p.expr, syntax.Perl)
			if err != nil {
				return nil, err
			}
			p.literals = required(re)
		} else {
			keyValue := strings.SplitN(part, ":", 2)
			if len(keyValue) < 2 {
				continue
			}

			switch keyValue[0] {
			case "confidence":
				conf, err := strconv.Atoi(keyValue[1])
				if err != nil {
					// If conversion fails, keep default confidence
					p.Confidence = 100
				} else {
					p.Confidence = conf
				}
			case "version":
				p.Version = keyValue[1]
			}
		}
	}
	return p, nil
}

func (p *ParsedPattern) Evaluate(target string) (bool, string) {
	if p.SkipRegex {
		return true, ""
	}
	p.once.Do(func() { p.regex, _ = regexp.Compile(p.expr) })
	if p.regex == nil {
		return false, ""
	}

	submatches := p.regex.FindStringSubmatch(target)
	if len(submatches) == 0 {
		return false, ""
	}
	extractedVersion, _ := p.extractVersion(submatches)
	return true, extractedVersion
}

// extractVersion uses the provided pattern to extract version information from a target string.
func (p *ParsedPattern) extractVersion(submatches []string) (string, error) {
	if len(submatches) == 0 {
		return "", nil // No matches found
	}

	result := p.Version
	for i, match := range submatches[1:] { // Start from 1 to skip the entire match
		placeholder := fmt.Sprintf("\\%d", i+1)
		result = strings.ReplaceAll(result, placeholder, match)
	}

	// Evaluate any ternary expressions in the result
	result, err := evaluateVersionExpression(result, submatches[1:])
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result), nil
}

// evaluateVersionExpression handles ternary expressions in version strings.
func evaluateVersionExpression(expression string, submatches []string) (string, error) {
	if strings.Contains(expression, "?") {
		parts := strings.Split(expression, "?")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid ternary expression: %s", expression)
		}

		trueFalseParts := strings.Split(parts[1], ":")
		if len(trueFalseParts) != 2 {
			return "", fmt.Errorf("invalid true/false parts in ternary expression: %s", expression)
		}

		if trueFalseParts[0] != "" { // Simple existence check
			if len(submatches) == 0 {
				return trueFalseParts[1], nil
			}
			return trueFalseParts[0], nil
		}
		if trueFalseParts[1] == "" {
			if len(submatches) == 0 {
				return "", nil
			}
			return trueFalseParts[0], nil
		}
		return trueFalseParts[1], nil
	}

	return expression, nil
}
