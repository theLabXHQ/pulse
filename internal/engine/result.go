package engine

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // file naming only
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/theLabXHQ/pulse/internal/extract"
	"github.com/theLabXHQ/pulse/internal/output"
	"github.com/theLabXHQ/pulse/internal/probe"
	"github.com/theLabXHQ/pulse/internal/version"
)

var tlsVersions = map[uint16]string{
	tls.VersionTLS10: "tls10", tls.VersionTLS11: "tls11", tls.VersionTLS12: "tls12", tls.VersionTLS13: "tls13",
}

func (e *Engine) buildResult(t *task, r *probe.Response) *output.Result {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	cl := r.ContentLength
	if cl <= 0 {
		cl = int64(len(r.Body))
	}
	words, lines := extract.Counts(r.Body)
	res := &output.Result{
		Schema:         version.SchemaVersion,
		Timestamp:      time.Now().UTC(),
		Input:          t.input,
		DiscoveredFrom: t.via,
		URL:            r.URL,
		FinalURL:       r.FinalURL,
		Scheme:         r.Scheme,
		Host:           t.spec.Host,
		Port:           r.Port,
		Path:           pathOrSlash(t.spec.Path),
		Method:         t.spec.Method,
		IP:             r.IP,
		StatusCode:     r.StatusCode,
		ContentLength:  cl,
		BodyBytes:      len(r.Body),
		BodyTruncated:  r.BodyTruncated,
		ContentType:    ct,
		WebServer:      r.Header.Get("Server"),
		Location:       r.Header.Get("Location"),
		HTTPVersion:    r.Proto,
		Words:          words,
		Lines:          lines,
		Chain:          r.Chain,
		Timing:         r.Timing,
		ConnReused:     r.Reused,
		Warnings:       r.Warnings,
	}
	if len(r.Attempts) > 1 {
		res.Attempts = r.Attempts
	}
	if extract.IsTitleCandidate(ct, r.Body) {
		res.Title = extract.Title(r.Body, r.Header.Get("Content-Type"))
	}
	if r.TLS != nil {
		res.TLS = tlsInfo(r.TLS)
	}
	if len(e.cfg.Hashes) > 0 {
		res.Hashes = make(map[string]string, len(e.cfg.Hashes))
		for _, a := range e.cfg.Hashes {
			res.Hashes["body_"+a] = extract.Hash(a, r.Body)
			res.Hashes["header_"+a] = extract.Hash(a, []byte(headerBlock(r))) // header hash
		}
	}
	if e.cfg.IncludeHeaders || e.cfg.IncludeBody {
		res.Headers = make(map[string]string, len(r.Header))
		for k, v := range r.Header {
			res.Headers[strings.ToLower(k)] = strings.Join(v, ", ")
		}
	}
	if e.cdn != nil {
		if ip, err := netip.ParseAddr(r.IP); err == nil {
			if m, ok := e.cdn.Lookup(ip); ok {
				// A cloud range (AWS, Azure, ...) is named but is
				// not a CDN — an EC2 host answers for itself.
				res.CDN, res.CDNName, res.CDNType = m.Type != "cloud", m.Name, m.Type
			}
		}
	}
	return res
}

func pathOrSlash(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func tlsInfo(cs *tls.ConnectionState) *output.TLSInfo {
	info := &output.TLSInfo{
		Version: tlsVersions[cs.Version],
		Cipher:  tls.CipherSuiteName(cs.CipherSuite),
		ALPN:    cs.NegotiatedProtocol,
	}
	if len(cs.PeerCertificates) == 0 {
		return info
	}
	c := cs.PeerCertificates[0]
	info.SubjectCN = c.Subject.CommonName
	info.SubjectAN = append(info.SubjectAN, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		info.SubjectAN = append(info.SubjectAN, ip.String())
	}
	info.IssuerCN = c.Issuer.CommonName
	info.IssuerOrg = c.Issuer.Organization
	info.NotBefore, info.NotAfter = c.NotBefore.UTC(), c.NotAfter.UTC()
	info.Expired = time.Now().After(c.NotAfter)
	info.SelfSigned = bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
	sum := sha256.Sum256(c.Raw)
	info.SHA256 = hex.EncodeToString(sum[:])
	return info
}

// headerBlock renders the status line and headers like they appeared on the
// wire (canonicalized), for matchers and stored responses.
func headerBlock(r *probe.Response) string {
	var b strings.Builder
	b.WriteString(r.Proto)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(r.StatusCode))
	b.WriteByte(' ')
	b.WriteString(http.StatusText(r.StatusCode))
	b.WriteString("\r\n")
	_ = r.Header.Write(&b)
	return b.String()
}

// store writes request line, response headers and body to
// <dir>/response/<host_port>/<sha1(method url)>.txt.
func (e *Engine) store(res *output.Result, headers string, body []byte) {
	hostDir := strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(res.Host + "_" + strconv.Itoa(res.Port))
	dir := filepath.Join(e.cfg.StoreDir, "response", hostDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.logf("error", "store response: %v", err)
		return
	}
	sum := sha1.Sum([]byte(res.Method + " " + res.URL)) //nolint:gosec
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".txt")
	var b bytes.Buffer
	b.WriteString(res.Method + " " + res.URL + "\n\n")
	b.WriteString(headers)
	b.WriteString("\r\n")
	b.Write(body)
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		e.logf("error", "store response: %v", err)
		return
	}
	res.StoredPath = path
}

// favicon resolves and hashes the page's favicon, trying at most two
// network candidates so a site without an icon costs at most two requests.
func (e *Engine) favicon(ctx context.Context, pageURL string, body []byte, buf *bytes.Buffer) *output.Favicon {
	tries := 0
	var lastErr string
	for _, cand := range extract.FaviconCandidates(body, pageURL) {
		if strings.HasPrefix(strings.ToLower(cand), "data:") {
			if data, ok := decodeDataURI(cand); ok {
				return &output.Favicon{URL: "data:", MMH3: extract.FaviconHash(data), MD5: extract.Hash("md5", data)}
			}
			continue
		}
		if tries == 2 {
			break
		}
		tries++
		if err := e.BeforeAttempt(ctx); err != nil {
			return &output.Favicon{Err: err.Error()}
		}
		r, f := e.client.Fetch(ctx, cand, buf)
		if f != nil {
			lastErr = string(f.Class)
			continue
		}
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if r.StatusCode != http.StatusOK || len(r.Body) == 0 || strings.Contains(ct, "text/html") {
			lastErr = "no icon at " + cand + " (status " + strconv.Itoa(r.StatusCode) + ")"
			continue
		}
		return &output.Favicon{URL: cand, MMH3: extract.FaviconHash(r.Body), MD5: extract.Hash("md5", r.Body)}
	}
	if lastErr == "" {
		lastErr = "no favicon found"
	}
	return &output.Favicon{Err: lastErr}
}

func decodeDataURI(s string) ([]byte, bool) {
	i := strings.IndexByte(s, ',')
	if i < 0 || !strings.Contains(strings.ToLower(s[:i]), ";base64") {
		return nil, false
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s[i+1:]))
	return data, err == nil
}
