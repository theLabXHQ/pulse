package extract

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// FaviconScanLimit bounds how much of the page is tokenized for <link> icons.
const FaviconScanLimit = 128 << 10

// FaviconCandidates returns icon URLs declared in the page (resolved against
// pageURL and <base href>), followed by /favicon.ico as the conventional
// fallback. data: URIs are returned as-is.
func FaviconCandidates(body []byte, pageURL string) []string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	if len(body) > FaviconScanLimit {
		body = body[:FaviconScanLimit]
	}
	var hrefs []string
	z := html.NewTokenizer(bytes.NewReader(body))
loop:
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			break loop
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			if (tag != "link" && tag != "base") || !hasAttr {
				if tag == "body" {
					break loop
				}
				continue
			}
			var rel, href string
			for {
				k, v, more := z.TagAttr()
				switch string(k) {
				case "rel":
					rel = strings.ToLower(string(v))
				case "href":
					href = strings.TrimSpace(string(v))
				}
				if !more {
					break
				}
			}
			if href == "" {
				continue
			}
			if tag == "base" {
				if b, err := base.Parse(href); err == nil {
					base = b
				}
				continue
			}
			for _, tok := range strings.Fields(rel) {
				if tok == "icon" || tok == "shortcut" || tok == "apple-touch-icon" || tok == "mask-icon" {
					hrefs = append(hrefs, href)
					break
				}
			}
		}
	}
	out := make([]string, 0, len(hrefs)+1)
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, h := range hrefs {
		if strings.HasPrefix(strings.ToLower(h), "data:") {
			add(h)
			continue
		}
		if u, err := base.Parse(h); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			add(u.String())
		}
	}
	if u, err := base.Parse("/favicon.ico"); err == nil {
		add(u.String())
	}
	return out
}
