package output

import (
	"slices"
	"strconv"
	"strings"
)

// Pulse's palette: brackets dim so the eye lands on values; status bold by
// class; the title, the line's main content, bold in the terminal's own
// foreground (white would vanish on light themes); server and technology
// in cyan/blue; secondary numbers and hashes dim. Plain text (no color)
// is a stable, script-friendly format.
const (
	cReset   = "\x1b[0m"
	cBold    = "\x1b[1m"
	cDim     = "\x1b[2m"
	cRed     = "\x1b[31m"
	cGreen   = "\x1b[32m"
	cYellow  = "\x1b[33m"
	cBlue    = "\x1b[94m"
	cMagenta = "\x1b[35m"
	cCyan    = "\x1b[36m"
)

// FormatText renders a result as "URL [field] [field] ...".
func FormatText(r *Result, f TextFields, color bool) string {
	var b strings.Builder
	b.Grow(128)
	b.WriteString(clean(r.URL))
	open, close := " [", "]"
	if color {
		open, close = " "+cDim+"["+cReset, cDim+"]"+cReset
	}
	field := func(s, c string) {
		s = clean(s)
		b.WriteString(open)
		if color && c != "" {
			b.WriteString(c)
			b.WriteString(s)
			b.WriteString(cReset)
		} else {
			b.WriteString(s)
		}
		b.WriteString(close)
	}
	if f.Probe {
		if r.Failed {
			field("FAILED", cBold+cRed)
		} else {
			field("SUCCESS", cBold+cGreen)
		}
	}
	if r.Failed {
		if r.Error != nil {
			field(string(r.Error.Class), cRed)
		}
		return b.String()
	}
	if f.StatusCode {
		if len(r.Chain) > 0 {
			codes := make([]string, len(r.Chain))
			for i, h := range r.Chain {
				codes[i] = statusColor(h.StatusCode, color)
			}
			b.WriteString(open + strings.Join(codes, ",") + close)
		} else {
			b.WriteString(open + statusColor(r.StatusCode, color) + close)
		}
	}
	if f.ContentLength {
		field(strconv.FormatInt(r.ContentLength, 10), cDim)
	}
	if f.ContentType && r.ContentType != "" {
		field(r.ContentType, cDim)
	}
	if f.Location && r.Location != "" {
		field(r.Location, cYellow)
	}
	if f.Location && r.FinalURL != "" {
		field(r.FinalURL, cYellow)
	}
	if f.Method {
		field(r.Method, cDim)
	}
	if f.Title && r.Title != "" {
		field(r.Title, cBold)
	}
	if f.WebServer && r.WebServer != "" {
		field(r.WebServer, cCyan)
	}
	if f.Tech && len(r.Tech) > 0 {
		field(strings.Join(r.Tech, ","), cBlue)
	}
	if f.IP && r.IP != "" {
		field(r.IP, cDim)
	}
	if f.CDN && r.CDN {
		field(r.CDNName, cYellow)
	}
	if f.CNAME && len(r.CNAME) > 0 {
		field(r.CNAME[0], cDim) // the first; JSON has the chain
	}
	if f.Extracts {
		for _, k := range sortedKeys2(r.Extracts) {
			field(strings.Join(r.Extracts[k], ","), cMagenta)
		}
	}
	if f.BodyPreview && r.BodyPreview != "" {
		field(r.BodyPreview, "")
	}
	if f.VHost && r.VHost {
		field("vhost", cYellow)
	}
	if f.Pipeline && r.Pipeline {
		field("pipeline", cYellow)
	}
	if f.ASN && r.ASN != nil {
		field(r.ASN.AsNumber+", "+r.ASN.AsName+", "+r.ASN.AsCountry, cDim)
	}
	if f.HTTPVersion && r.HTTPVersion != "" {
		field(r.HTTPVersion, cDim)
	}
	if f.TLS && r.TLS != nil {
		field(r.TLS.Version, cDim)
	}
	if f.ResponseTime {
		field(strconv.FormatFloat(r.Timing.Total, 'f', 0, 64)+"ms", cDim)
	}
	if f.Favicon && r.Favicon != nil && r.Favicon.MMH3 != "" {
		field(r.Favicon.MMH3, cDim)
	}
	if f.Hash && len(r.Hashes) > 0 {
		for _, k := range sortedKeys(r.Hashes) {
			field(r.Hashes[k], cDim)
		}
	}
	if f.Lines {
		field(strconv.Itoa(r.Lines), cDim)
	}
	if f.Words {
		field(strconv.Itoa(r.Words), cDim)
	}
	return b.String()
}

func statusColor(code int, color bool) string {
	s := strconv.Itoa(code)
	if !color {
		return s
	}
	c := cBlue // 1xx and anything odd
	switch {
	case code >= 200 && code < 300:
		c = cGreen
	case code >= 300 && code < 400:
		c = cYellow
	case code >= 400 && code < 500:
		c = cRed
	case code >= 500:
		c = cMagenta
	}
	return cBold + c + s + cReset
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func sortedKeys2(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
