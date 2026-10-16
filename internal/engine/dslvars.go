package engine

import (
	"net/http"
	"sort"
	"strings"

	"github.com/theLabXHQ/pulse/internal/dsl"
	"github.com/theLabXHQ/pulse/internal/output"
)

// dslVars exposes a result to -mdc/-fdc expressions. Names follow the JSON
// fields (plus a few common aliases).
var dslVars = map[string]func(r *output.Result, body []byte, h http.Header) any{
	"status_code":    func(r *output.Result, _ []byte, _ http.Header) any { return float64(r.StatusCode) },
	"content_length": func(r *output.Result, _ []byte, _ http.Header) any { return float64(r.ContentLength) },
	"body_bytes":     func(r *output.Result, _ []byte, _ http.Header) any { return float64(r.BodyBytes) },
	"words":          func(r *output.Result, _ []byte, _ http.Header) any { return float64(r.Words) },
	"lines":          func(r *output.Result, _ []byte, _ http.Header) any { return float64(r.Lines) },
	"title":          func(r *output.Result, _ []byte, _ http.Header) any { return r.Title },
	"body":           func(_ *output.Result, b []byte, _ http.Header) any { return string(b) },
	"header":         func(_ *output.Result, _ []byte, h http.Header) any { return headerText(h) },
	"webserver":      func(r *output.Result, _ []byte, _ http.Header) any { return r.WebServer },
	"server":         func(r *output.Result, _ []byte, _ http.Header) any { return r.WebServer },
	"content_type":   func(r *output.Result, _ []byte, _ http.Header) any { return r.ContentType },
	"location":       func(r *output.Result, _ []byte, _ http.Header) any { return r.Location },
	"url":            func(r *output.Result, _ []byte, _ http.Header) any { return r.URL },
	"final_url":      func(r *output.Result, _ []byte, _ http.Header) any { return r.FinalURL },
	"input":          func(r *output.Result, _ []byte, _ http.Header) any { return r.Input },
	"host":           func(r *output.Result, _ []byte, _ http.Header) any { return r.Host },
	"port":           func(r *output.Result, _ []byte, _ http.Header) any { return float64(r.Port) },
	"scheme":         func(r *output.Result, _ []byte, _ http.Header) any { return r.Scheme },
	"path":           func(r *output.Result, _ []byte, _ http.Header) any { return r.Path },
	"method":         func(r *output.Result, _ []byte, _ http.Header) any { return r.Method },
	"ip":             func(r *output.Result, _ []byte, _ http.Header) any { return r.IP },
	"http_version":   func(r *output.Result, _ []byte, _ http.Header) any { return r.HTTPVersion },
	"response_time":  func(r *output.Result, _ []byte, _ http.Header) any { return r.Timing.Total },
	"tech":           func(r *output.Result, _ []byte, _ http.Header) any { return append([]string(nil), r.Tech...) },
	"cdn":            func(r *output.Result, _ []byte, _ http.Header) any { return r.CDN },
	"cdn_name":       func(r *output.Result, _ []byte, _ http.Header) any { return r.CDNName },
	"cdn_type":       func(r *output.Result, _ []byte, _ http.Header) any { return r.CDNType },
	"tls_version": func(r *output.Result, _ []byte, _ http.Header) any {
		if r.TLS == nil {
			return ""
		}
		return r.TLS.Version
	},
	"favicon": func(r *output.Result, _ []byte, _ http.Header) any {
		if r.Favicon == nil {
			return ""
		}
		return r.Favicon.MMH3
	},
	"asn": func(r *output.Result, _ []byte, _ http.Header) any {
		if r.ASN == nil {
			return ""
		}
		return r.ASN.AsNumber
	},
}

// DSLVariables lists the names -mdc/-fdc expressions may use.
func DSLVariables() []string {
	out := make([]string, 0, len(dslVars))
	for k := range dslVars {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func varsFor(r *output.Result, body []byte, h http.Header) dsl.Vars {
	return func(name string) (any, bool) {
		f, ok := dslVars[name]
		if !ok {
			return nil, false
		}
		return f(r, body, h), true
	}
}

func headerText(h http.Header) string {
	var b strings.Builder
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	return b.String()
}
