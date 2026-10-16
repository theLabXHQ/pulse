// Package output defines the result schema and serializes results as text,
// JSONL or CSV through a single buffered writer goroutine.
package output

import (
	"time"

	"github.com/theLabXHQ/pulse/internal/probe"
)

// Result is one line of output. Field names are the stable pulse.v1 schema
// documented in docs/SCHEMA.md; optional fields are omitted when empty.
type Result struct {
	Schema         string              `json:"schema"`
	Timestamp      time.Time           `json:"timestamp"`
	Input          string              `json:"input"`
	DiscoveredFrom string              `json:"discovered_from,omitempty"` // "tls:<host>" or "csp:<host>"
	URL            string              `json:"url"`
	FinalURL       string              `json:"final_url,omitempty"`
	Scheme         string              `json:"scheme,omitempty"`
	Host           string              `json:"host"`
	Port           int                 `json:"port,omitempty"`
	Path           string              `json:"path,omitempty"`
	Method         string              `json:"method"`
	IP             string              `json:"ip,omitempty"`
	StatusCode     int                 `json:"status_code,omitempty"`
	ContentLength  int64               `json:"content_length"`
	BodyBytes      int                 `json:"body_bytes"`
	BodyTruncated  bool                `json:"body_truncated,omitempty"`
	ContentType    string              `json:"content_type,omitempty"`
	Title          string              `json:"title,omitempty"`
	WebServer      string              `json:"webserver,omitempty"`
	Location       string              `json:"location,omitempty"`
	HTTPVersion    string              `json:"http_version,omitempty"`
	Words          int                 `json:"words"`
	Lines          int                 `json:"lines"`
	Chain          []probe.Hop         `json:"chain,omitempty"`
	TLS            *TLSInfo            `json:"tls,omitempty"`
	Timing         probe.Timing        `json:"timing"`
	ConnReused     bool                `json:"conn_reused,omitempty"`
	Attempts       []probe.AttemptInfo `json:"attempts,omitempty"`
	Hashes         map[string]string   `json:"hash,omitempty"`
	Favicon        *Favicon            `json:"favicon,omitempty"`
	Tech           []string            `json:"tech,omitempty"`
	CDN            bool                `json:"cdn,omitempty"`
	CDNName        string              `json:"cdn_name,omitempty"`
	CDNType        string              `json:"cdn_type,omitempty"` // cdn, waf or cloud
	ASN            *ASNInfo            `json:"asn,omitempty"`
	VHost          bool                `json:"vhost,omitempty"`
	Pipeline       bool                `json:"pipeline,omitempty"`
	CNAME          []string            `json:"cname,omitempty"`
	BodyPreview    string              `json:"body_preview,omitempty"`
	Extracts       map[string][]string `json:"extracts,omitempty"` // -er regex or -ep preset -> matches
	Headers        map[string]string   `json:"headers,omitempty"`
	Body           string              `json:"body,omitempty"`
	StoredPath     string              `json:"stored_response_path,omitempty"`
	Warnings       []string            `json:"warnings,omitempty"`
	Failed         bool                `json:"failed,omitempty"`
	Error          *ErrorInfo          `json:"error,omitempty"`

	// OnWritten, if set, is called once the result has been written and
	// flushed (resume accounting: a line counts as done only when its
	// output is durable). It is never called if writing fails.
	OnWritten func() `json:"-"`
}

// TLSInfo summarizes the negotiated TLS session and leaf certificate.
type TLSInfo struct {
	Version    string    `json:"version"`
	Cipher     string    `json:"cipher"`
	ALPN       string    `json:"alpn,omitempty"`
	SubjectCN  string    `json:"subject_cn,omitempty"`
	SubjectAN  []string  `json:"subject_an,omitempty"`
	IssuerCN   string    `json:"issuer_cn,omitempty"`
	IssuerOrg  []string  `json:"issuer_org,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed,omitempty"`
	Expired    bool      `json:"expired,omitempty"`
	SHA256     string    `json:"fingerprint_sha256,omitempty"`
}

// Favicon is the result of favicon enrichment.
// ASNInfo describes the autonomous system of the connected IP.
type ASNInfo struct {
	AsNumber  string   `json:"as_number"` // "AS13335"
	AsName    string   `json:"as_name"`
	AsCountry string   `json:"as_country"`
	AsRange   []string `json:"as_range"`
}

type Favicon struct {
	URL  string `json:"url,omitempty"`
	MMH3 string `json:"mmh3,omitempty"`
	MD5  string `json:"md5,omitempty"`
	Err  string `json:"error,omitempty"`
}

// ErrorInfo describes why a probe failed.
type ErrorInfo struct {
	Class   probe.Class `json:"class"`
	Phase   probe.Phase `json:"phase,omitempty"`
	Message string      `json:"message"`
}
