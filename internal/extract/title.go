// Package extract derives metadata from response bodies. Every function is
// pure and bounded: it inspects at most a fixed prefix of the body.
package extract

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
)

// TitleScanLimit bounds how much of a body is tokenized to find <title>.
// Titles live in <head>, but modern pages inline hundreds of KiB of CSS/JS
// before it (spring.io: 333 KiB, wix.com: 284 KiB), so the limit matches the
// default body limit. Scanning stops at the first title.
const TitleScanLimit = 1 << 20

// MaxTitleLen caps the reported title length (in bytes).
const MaxTitleLen = 1024

// IsTitleCandidate reports whether a content type can carry an HTML title.
// An empty content type is sniffed, because many servers omit it.
func IsTitleCandidate(contentType string, body []byte) bool {
	ct := strings.ToLower(contentType)
	if ct == "" {
		head := body
		if len(head) > 512 {
			head = head[:512]
		}
		return bytes.Contains(bytes.ToLower(head), []byte("<html")) || bytes.Contains(bytes.ToLower(head), []byte("<title"))
	}
	return strings.Contains(ct, "html") || strings.Contains(ct, "xml")
}

// Title returns the text of the first <title> element (not inside <svg>),
// decoded to UTF-8 using the Content-Type/meta charset, whitespace-collapsed.
// A title inside <noscript> counts: bot-challenge pages put theirs there.
func Title(body []byte, contentType string) string {
	if len(body) > TitleScanLimit {
		body = body[:TitleScanLimit]
	}
	return title(body, body, contentType, true)
}

// title scans doc; body is the whole document (for charset detection).
func title(doc, body []byte, contentType string, noscript bool) string {
	z := html.NewTokenizer(bytes.NewReader(doc))
	inTitle, inNoscript := false, false
	svgDepth := 0
	var raw []byte
	for {
		switch z.Next() {
		case html.ErrorToken:
			if inTitle {
				return finishTitle(raw, body, contentType)
			}
			return ""
		case html.StartTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "svg":
				svgDepth++
			case "title":
				if svgDepth == 0 {
					inTitle = true
				}
			case "noscript":
				// The tokenizer returns noscript content as raw text.
				inNoscript = noscript
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "svg":
				if svgDepth > 0 {
					svgDepth--
				}
			case "title":
				if inTitle {
					return finishTitle(raw, body, contentType)
				}
			case "noscript":
				inNoscript = false
			}
		case html.TextToken:
			if inNoscript && !inTitle {
				if t := title(z.Raw(), body, contentType, false); t != "" {
					return t
				}
				continue
			}
			if inTitle {
				raw = append(raw, z.Raw()...)
				if len(raw) > 4*MaxTitleLen {
					return finishTitle(raw, body, contentType)
				}
			}
		}
	}
}

func finishTitle(raw, body []byte, contentType string) string {
	if !utf8.Valid(raw) {
		raw = toUTF8(raw, body, contentType)
	}
	t := html.UnescapeString(string(raw))
	t = strings.Join(strings.Fields(t), " ")
	if len(t) > MaxTitleLen {
		t = t[:MaxTitleLen]
		for !utf8.ValidString(t) {
			t = t[:len(t)-1]
		}
	}
	return t
}

// toUTF8 converts raw from the charset declared for the document.
func toUTF8(raw, body []byte, contentType string) []byte {
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	enc, _, _ := charset.DetermineEncoding(head, contentType)
	if enc == nil {
		return raw
	}
	out, _, err := transform.Bytes(enc.NewDecoder(), raw)
	if err != nil {
		return bytes.ToValidUTF8(raw, []byte("�"))
	}
	return out
}

// Counts returns word and line counts: words are separated
// by single spaces and lines by "\n" after trimming surrounding whitespace.
func Counts(body []byte) (words, lines int) {
	if len(body) == 0 {
		return 0, 0
	}
	return bytes.Count(body, []byte{' '}) + 1, bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
}

// BodyUTF8 returns a text body decoded to UTF-8 using the Content-Type or
// <meta> charset, for string matching and JSON output. UTF-8 bodies and
// non-text content types are returned unchanged.
func BodyUTF8(body []byte, contentType string) []byte {
	if utf8.Valid(body) {
		return body
	}
	ct := strings.ToLower(contentType)
	if ct != "" && !strings.Contains(ct, "text") && !strings.Contains(ct, "html") &&
		!strings.Contains(ct, "xml") && !strings.Contains(ct, "json") && !strings.Contains(ct, "javascript") {
		return body
	}
	return toUTF8(body, body, contentType)
}
