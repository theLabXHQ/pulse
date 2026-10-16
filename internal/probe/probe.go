package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theLabXHQ/pulse/internal/target"
)

// Spec describes one probe: a host:port with a scheme policy and a path.
type Spec struct {
	Host   string
	Port   int    // 0 = default port of each scheme tried
	Scheme string // target.SchemeAuto / SchemeHTTP / SchemeHTTPS
	Path   string
	Method string // "" = client default
	Auth   string // "user:password" for HTTP Basic auth (from the target URL)
}

// Hop is one response in a redirect chain.
type Hop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location,omitempty"`
}

// AttemptInfo records one scheme attempt; it is the evidence behind the
// scheme that a result reports.
type AttemptInfo struct {
	Scheme string `json:"scheme"`
	Port   int    `json:"port"`
	Status int    `json:"status_code,omitempty"`
	Error  Class  `json:"error,omitempty"`
}

// Response is a successful probe. Body aliases the caller's buffer and is
// only valid until that buffer is reused.
type Response struct {
	URL           string // URL of the first request
	FinalURL      string // URL of the last hop ("" if no redirect was followed)
	Scheme        string
	Port          int
	StatusCode    int
	Proto         string
	Header        http.Header
	ContentLength int64 // from the header; -1 if absent
	Body          []byte
	BodyTruncated bool
	Encoding      string
	Warnings      []string
	Chain         []Hop // every hop including the final one when redirects were followed
	TLS           *tls.ConnectionState
	IP            string
	Reused        bool
	Timing        Timing
	Attempts      []AttemptInfo
}

// Failure is an unsuccessful probe together with the attempts made.
type Failure struct {
	*Error
	URL      string
	Attempts []AttemptInfo
	Timing   Timing
}

var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// Probe runs a probe, choosing the scheme as follows when Scheme is auto:
//
//   - try the likelier scheme first (target.SchemeOrder);
//   - on a host-level failure (DNS, policy) stop: the other scheme cannot work;
//   - on a connection-level failure (refused, connect timeout) stop if the
//     other scheme would use the same port, otherwise try it;
//   - on TLS/protocol failures try the other scheme on the same port, except
//     after a plaintext request timed out waiting for a response;
//   - a plaintext 400 on an explicit port is retried over TLS, because many
//     TLS-only servers answer plaintext with "400 plain HTTP sent to HTTPS".
func (c *Client) Probe(ctx context.Context, s Spec, buf *bytes.Buffer) (*Response, *Failure) {
	start := time.Now()
	if s.Method == "" {
		s.Method = c.opts.Method
	}
	finish := func(r *Response, f *Failure) (*Response, *Failure) {
		total := ms(time.Since(start))
		if r != nil {
			r.Timing.Total = total
		} else {
			f.Timing.Total = total
		}
		return r, f
	}

	if s.Scheme == target.SchemeHTTP || s.Scheme == target.SchemeHTTPS {
		r, f := c.attempt(ctx, s, s.Scheme, buf, nil)
		return finish(r, f)
	}

	order := target.SchemeOrder(s.Port)
	r, f := c.attempt(ctx, s, order[0], buf, nil)
	if f == nil {
		if order[0] == target.SchemeHTTP && s.Port != 0 && r.StatusCode == http.StatusBadRequest {
			alt := bufPool.Get().(*bytes.Buffer)
			defer func() {
				if alt.Cap() <= 4<<20 {
					bufPool.Put(alt)
				}
			}()
			r2, f2 := c.attempt(ctx, s, target.SchemeHTTPS, alt, r.Attempts)
			if f2 == nil {
				// Copy into the caller's buffer so the body outlives alt.
				buf.Reset()
				buf.Write(r2.Body)
				r2.Body = buf.Bytes()
				return finish(r2, nil)
			}
			r.Attempts = f2.Attempts
		}
		return finish(r, nil)
	}
	if f.HostLevel() || ctx.Err() != nil {
		return finish(nil, f)
	}
	if s.Port != 0 && (f.ConnectionLevel() || (order[0] == target.SchemeHTTP && f.Class == ClassResponseTimout)) {
		// Same port: a dead endpoint stays dead. A plaintext request that got
		// no answer is not a TLS port either: TLS stacks reject "GET /" as an
		// invalid record header immediately rather than waiting.
		return finish(nil, f)
	}
	r2, f2 := c.attempt(ctx, s, order[1], buf, f.Attempts)
	if f2 == nil {
		return finish(r2, nil)
	}
	// Report the failure that says most about the target: a TLS/protocol
	// error on the first attempt is more informative than "refused" on :80.
	if f2.ConnectionLevel() && !f.ConnectionLevel() {
		f.Attempts = f2.Attempts
		return finish(nil, f)
	}
	return finish(nil, f2)
}

// attempt performs one scheme attempt with retries for transient errors.
func (c *Client) attempt(ctx context.Context, s Spec, scheme string, buf *bytes.Buffer, prev []AttemptInfo) (*Response, *Failure) {
	port := s.Port
	if port == 0 {
		port = target.DefaultPort(scheme)
	}
	u := target.BuildURL(scheme, s.Host, port, s.Path)
	if c.opts.LeaveDefaultPorts && port == target.DefaultPort(scheme) {
		path := s.Path
		if path == "" {
			path = "/"
		}
		u = scheme + "://" + target.HostPort(s.Host, port) + path // Host header keeps the port too
	}
	var (
		r *Response
		f *Failure
	)
	for try := 0; ; try++ {
		if c.opts.BeforeAttempt != nil {
			if err := c.opts.BeforeAttempt(ctx); err != nil {
				f = &Failure{Error: &Error{Class: ClassCanceled, Phase: PhaseRequest, Err: err}, URL: u}
				break
			}
		}
		if c.opts.Raw != nil {
			r, f = c.rawFetch(ctx, scheme, s.Host, port, s.Path, buf)
		} else {
			fctx := ctx
			if s.Auth != "" {
				fctx = context.WithValue(ctx, authKey{}, s.Auth)
			}
			r, f = c.fetch(fctx, c.rt, s.Method, u, buf)
			if f != nil && strings.Contains(f.Err.Error(), "malformed MIME header") && c.proxyHost == "" {
				r, f = c.lenientFetch(fctx, s, scheme, port, u, buf)
			}
			if c.imp != nil && r != nil && scheme == target.SchemeHTTPS && looksBlocked(r) {
				r, f = c.retryImpersonated(fctx, s.Method, u, r, buf)
			}
		}
		if f == nil || try >= c.opts.Retries || !f.Transient() || ctx.Err() != nil {
			break
		}
		backoff := time.Duration(200<<try) * time.Millisecond
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
	}
	info := AttemptInfo{Scheme: scheme, Port: port}
	attempts := append(append([]AttemptInfo(nil), prev...), info)
	if f != nil {
		attempts[len(attempts)-1].Error = f.Class
		f.Attempts = attempts
		return nil, f
	}
	attempts[len(attempts)-1].Status = r.StatusCode
	r.Scheme, r.Port, r.Attempts = scheme, port, attempts
	return r, nil
}

type hostKey struct{}

type authKey struct{}

// WithHost makes requests made with ctx send host as the Host header (the
// connection and TLS SNI still follow the URL), e.g. for -vhost.
func WithHost(ctx context.Context, host string) context.Context {
	return context.WithValue(ctx, hostKey{}, host)
}

// lenientFetch re-sends a request whose response Go rejected for control
// characters in its headers, parsing that response leniently.
func (c *Client) lenientFetch(ctx context.Context, s Spec, scheme string, port int, rawURL string, buf *bytes.Buffer) (*Response, *Failure) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, &Failure{Error: &Error{Class: ClassInvalid, Phase: PhaseRequest, Err: err}, URL: rawURL}
	}
	method := s.Method
	if method == "" {
		method = c.opts.Method
	}
	req, err := c.newRequest(ctx, method, u)
	if err != nil {
		return nil, &Failure{Error: &Error{Class: ClassInvalid, Phase: PhaseRequest, Err: err}, URL: rawURL}
	}
	var b bytes.Buffer
	if err := req.Write(&b); err != nil {
		return nil, &Failure{Error: &Error{Class: ClassInvalid, Phase: PhaseRequest, Err: err}, URL: rawURL}
	}
	return c.rawRoundTrip(ctx, b.Bytes(), true, method, scheme, s.Host, port, s.Path, buf)
}

// Fetch requests one absolute URL (used for enrichment such as favicons).
func (c *Client) Fetch(ctx context.Context, rawURL string, buf *bytes.Buffer) (*Response, *Failure) {
	return c.fetch(ctx, c.rt, http.MethodGet, rawURL, buf)
}

// retryImpersonated re-requests a blocked page with Chrome's TLS fingerprint
// and keeps whichever answer is not a block page. Go's own fingerprint and
// Chrome's are each blocked by different bot managers (Cloudflare checks
// that TLS and HTTP/2 fingerprints agree), so trying both covers more sites
// than either; the extra request is spent only on blocked pages.
func (c *Client) retryImpersonated(ctx context.Context, method, u string, blocked *Response, buf *bytes.Buffer) (*Response, *Failure) {
	if c.opts.BeforeAttempt != nil && c.opts.BeforeAttempt(ctx) != nil {
		return blocked, nil
	}
	saved := append([]byte(nil), blocked.Body...) // buf is reused by the retry
	r, f := c.fetch(ctx, c.imp, method, u, buf)
	if f == nil && !looksBlocked(r) {
		r.Warnings = append(r.Warnings, "tls_impersonated")
		return r, nil
	}
	buf.Reset()
	buf.Write(saved)
	blocked.Body = buf.Bytes()
	return blocked, nil
}

// fetch performs a request with its own timeout, following redirects if
// configured, and reads the final body into buf.
func (c *Client) fetch(ctx context.Context, rt http.RoundTripper, method, rawURL string, buf *bytes.Buffer) (*Response, *Failure) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, &Failure{Error: &Error{Class: ClassInvalid, Phase: PhaseRequest, Err: err}, URL: rawURL}
	}
	firstURL := u.String()
	origHost := u.Hostname()
	visited := map[string]bool{firstURL: true}
	var chain []Hop
	var warnings []string

	for hop := 0; ; hop++ {
		tr := newAttemptTrace()
		req, err := c.newRequest(tr.with(ctx), method, u)
		if err != nil {
			return nil, &Failure{Error: &Error{Class: ClassInvalid, Phase: PhaseRequest, Err: err}, URL: firstURL}
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			return nil, &Failure{Error: classify(err, tr, c.Proxied()), URL: firstURL, Timing: tr.timing()}
		}

		loc := resp.Header.Get("Location")
		isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != ""
		follow := (c.opts.FollowRedirects || c.opts.FollowHostRedirects) && isRedirect
		var next *url.URL
		if follow {
			if next, err = u.Parse(loc); err != nil || (next.Scheme != "http" && next.Scheme != "https") {
				follow = false
				warnings = append(warnings, "invalid_redirect_location")
			}
		}
		if follow && c.opts.FollowHostRedirects && !c.opts.FollowRedirects && !strings.EqualFold(next.Hostname(), origHost) {
			follow = false
		}
		if follow || len(chain) > 0 {
			chain = append(chain, Hop{URL: u.String(), StatusCode: resp.StatusCode, Location: loc})
		}
		if follow && visited[next.String()] {
			follow = false
			warnings = append(warnings, string(ClassRedirectLoop))
		}
		if follow && hop+1 > c.opts.MaxRedirects {
			follow = false
			warnings = append(warnings, string(ClassTooManyRedirs))
		}
		if follow {
			drain(resp.Body, 64<<10)
			visited[next.String()] = true
			switch resp.StatusCode {
			case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
				if method != http.MethodHead {
					method = http.MethodGet
				}
			}
			u = next
			continue
		}

		br := readBody(resp.Body, resp.Header.Get("Content-Encoding"), c.opts.MaxBodySize, buf)
		if br.truncated || br.readErr != nil {
			_ = resp.Body.Close() // do not drain an oversized/broken body; drop the connection
		} else {
			drain(resp.Body, 4<<10)
		}
		if br.readErr != nil {
			if errors.Is(br.readErr, context.DeadlineExceeded) || isTimeout(br.readErr) {
				warnings = append(warnings, "body_timeout")
			} else {
				warnings = append(warnings, "body_read_error")
			}
		}
		if br.undecodable {
			warnings = append(warnings, "undecoded_content_encoding")
		}
		out := &Response{
			URL:           firstURL,
			StatusCode:    resp.StatusCode,
			Proto:         resp.Proto,
			Header:        resp.Header,
			ContentLength: resp.ContentLength,
			Body:          buf.Bytes(),
			BodyTruncated: br.truncated,
			Encoding:      br.encoding,
			Warnings:      warnings,
			Chain:         chain,
			TLS:           resp.TLS,
			Timing:        tr.timing(),
		}
		if cl := resp.Header.Get("Content-Length"); cl != "" && out.ContentLength < 0 {
			if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
				out.ContentLength = n
			}
		}
		tr.mu.Lock()
		out.Reused = tr.reused
		if !c.Proxied() {
			out.IP = tr.remoteIP
		}
		tr.mu.Unlock()
		if len(chain) > 0 {
			out.FinalURL = u.String()
		}
		return out, nil
	}
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func (c *Client) newRequest(ctx context.Context, method string, u *url.URL) (*http.Request, error) {
	var body io.Reader
	if c.opts.Body != "" {
		body = strings.NewReader(c.opts.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	h := req.Header
	ua := c.opts.UserAgent
	if c.opts.RandomAgent {
		ua = browserAgents[rand.IntN(len(browserAgents))]
	}
	h.Set("User-Agent", ua)
	// A browser navigation Accept, matching the browser User-Agent: with
	// "*/*" CDNs treat the request as an API call and serve a different
	// page (Cloudflare drops its injected scripts, so tech detection misses
	// them).
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	h.Set("Accept-Encoding", "gzip, deflate")
	h.Set("Accept-Language", "en-US,en;q=0.9") // browsers always send one; its absence is a bot signal
	for k, vs := range c.opts.Headers {
		if strings.EqualFold(k, "Host") {
			if len(vs) > 0 {
				req.Host = vs[0]
			}
			continue
		}
		h[k] = vs
	}
	if host, ok := ctx.Value(hostKey{}).(string); ok {
		req.Host = host
	}
	if auth, ok := ctx.Value(authKey{}).(string); ok && req.Header.Get("Authorization") == "" {
		user, pass, _ := strings.Cut(auth, ":")
		req.SetBasicAuth(user, pass)
	}
	return req, nil
}
