package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/theLabXHQ/pulse/internal/target"
)

// RawRequest is a request read from a file (-request).
type RawRequest struct {
	Method string
	URI    string // as written: "/path?q" or an absolute URL
	Host   string // Host header
	Header http.Header
	Body   string
}

// ParseRawRequest reads an HTTP/1.x request as saved by Burp, a browser's
// dev tools or curl --trace. CRLF and bare LF line endings are both accepted.
func ParseRawRequest(data []byte) (*RawRequest, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	head, body, _ := strings.Cut(text, "\n\n")
	lines := strings.Split(strings.TrimLeft(head, "\n"), "\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("bad request line %q", lines[0])
	}
	rr := &RawRequest{Method: parts[0], URI: parts[1], Header: http.Header{}, Body: body}
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("bad header line %q", l)
		}
		k = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "Host" {
			rr.Host = v
			continue
		}
		rr.Header.Add(k, v)
	}
	if u, err := url.Parse(rr.URI); err == nil && u.IsAbs() && rr.Host == "" {
		rr.Host = u.Host
	}
	return rr, nil
}

// Path returns the request target as a path (absolute URLs reduced).
func (rr *RawRequest) Path() string {
	if u, err := url.Parse(rr.URI); err == nil && u.IsAbs() {
		p := u.EscapedPath()
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		if p == "" {
			p = "/"
		}
		return p
	}
	return rr.URI
}

// rawFetch sends c.opts.Raw unchanged over a fresh connection (-unsafe) and
// reads one response. There are no redirects and no Go normalization of the
// request; the connection still goes through the client's dialer (DNS
// cache, -deny policy) and TLS settings. The response is read for the
// method on the raw request line, whatever -x says.
func (c *Client) rawFetch(ctx context.Context, scheme, host string, port int, path string, buf *bytes.Buffer) (*Response, *Failure) {
	method, _, _ := strings.Cut(string(c.opts.Raw[:bytes.IndexByte(append(c.opts.Raw[:len(c.opts.Raw):len(c.opts.Raw)], '\n'), '\n')]), " ")
	return c.rawRoundTrip(ctx, c.opts.Raw, false, method, scheme, host, port, path, buf)
}

// rawRoundTrip sends request over a fresh connection via rawExchange and
// reads the body into a Response; shared by -unsafe and lenientFetch.
func (c *Client) rawRoundTrip(ctx context.Context, request []byte, lenient bool, method, scheme, host string, port int, path string, buf *bytes.Buffer) (*Response, *Failure) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	if path == "" {
		path = "/"
	}
	u := target.BuildURL(scheme, host, port, path)
	tr := newAttemptTrace()
	ctx = tr.with(ctx)
	resp, conn, state, err := c.rawExchange(ctx, request, lenient, method, scheme, host, port)
	if err != nil {
		return nil, &Failure{Error: classify(err, tr, false), URL: u, Timing: tr.timing()}
	}
	defer conn.Close()
	body := readBody(resp.Body, resp.Header.Get("Content-Encoding"), c.opts.MaxBodySize, buf)
	_ = resp.Body.Close()
	var warnings []string
	if body.readErr != nil {
		if errors.Is(body.readErr, context.DeadlineExceeded) || isTimeout(body.readErr) {
			warnings = append(warnings, "body_timeout")
		} else {
			warnings = append(warnings, "body_read_error")
		}
	}
	if body.undecodable {
		warnings = append(warnings, "undecoded_content_encoding")
	}
	if lenient {
		warnings = append(warnings, "malformed_headers")
	}
	out := &Response{
		URL: u, StatusCode: resp.StatusCode, Proto: resp.Proto, Header: resp.Header,
		ContentLength: resp.ContentLength, Body: buf.Bytes(), BodyTruncated: body.truncated,
		Encoding: body.encoding, Warnings: warnings, TLS: state, Timing: tr.timing(),
	}
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		out.IP = a.IP.String()
	}
	return out, nil
}

// rawExchange writes request bytes on a fresh connection and reads the
// response header (interim 1xx responses skipped). The caller reads the
// body and closes conn. With lenient, control characters in the response
// header blocks are replaced by spaces first: Go's parser rejects them
// ("malformed MIME header line"), which would make a live server look dead.
// ctx must carry the deadline.
func (c *Client) rawExchange(ctx context.Context, request []byte, lenient bool, method, scheme, host string, port int) (*http.Response, net.Conn, *tls.ConnectionState, error) {
	hooks := httptrace.ContextClientTrace(ctx)
	if hooks == nil {
		hooks = &httptrace.ClientTrace{}
	}
	// c.dial resolves, then connects with ctx: net.Dialer reports
	// ConnectStart/ConnectDone to the trace itself, after DNS.
	conn, err := c.dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*http.Response, net.Conn, *tls.ConnectionState, error) {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	var state *tls.ConnectionState
	if scheme == target.SchemeHTTPS {
		cfg := c.transport.TLSClientConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		cfg.NextProtos = []string{"http/1.1"}
		tc := tls.Client(conn, cfg)
		if hooks.TLSHandshakeStart != nil {
			hooks.TLSHandshakeStart()
		}
		err := tc.HandshakeContext(ctx)
		cs := tc.ConnectionState()
		if hooks.TLSHandshakeDone != nil {
			hooks.TLSHandshakeDone(cs, err)
		}
		if err != nil {
			return fail(err)
		}
		state = &cs
		conn = tc
	}
	if hooks.GotConn != nil {
		hooks.GotConn(httptrace.GotConnInfo{Conn: conn})
	}
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}
	if hooks.WroteRequest != nil {
		hooks.WroteRequest(httptrace.WroteRequestInfo{})
	}
	var src io.Reader = &firstByteReader{r: conn, hook: hooks.GotFirstResponseByte}
	if lenient {
		src = sanitizeHeaderBlock(src)
	}
	resp, err := readFinalResponse(bufio.NewReader(src), &http.Request{Method: method})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			err = context.DeadlineExceeded
		}
		return fail(err)
	}
	resp.TLS = state
	return resp, conn, state, nil
}

// readFinalResponse reads a response, skipping interim 1xx responses (103
// Early Hints, 100 Continue) as net/http's transport does; 101 is final.
func readFinalResponse(br *bufio.Reader, req *http.Request) (*http.Response, error) {
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
	}
}

// firstByteReader reports the first successful read.
type firstByteReader struct {
	r    interface{ Read([]byte) (int, error) }
	hook func()
	done bool
}

func (f *firstByteReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if n > 0 && !f.done {
		f.done = true
		if f.hook != nil {
			f.hook()
		}
	}
	return n, err
}

// sanitizeHeaderBlock passes r through, replacing control characters (other
// than CR, LF and tab) with spaces in the response header blocks: those of
// interim 1xx responses and of the final one. The body is left untouched.
func sanitizeHeaderBlock(r io.Reader) io.Reader {
	return &headerSanitizer{r: r}
}

type headerSanitizer struct {
	r      io.Reader
	tail   [3]byte // last bytes seen, to find the blank line across reads
	line   []byte  // start of the current block's status line
	inLine bool    // still reading the status line
	done   bool
}

func (h *headerSanitizer) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	for i := 0; i < n && !h.done; i++ {
		b := p[i]
		if !h.inLine && len(h.line) == 0 {
			h.inLine = true
		}
		if h.inLine {
			if b == '\n' {
				h.inLine = false
			} else if len(h.line) < 16 {
				h.line = append(h.line, b)
			}
		}
		// A header block ends at an empty line: LF LF or LF CR LF.
		end := b == '\n' && (h.tail[2] == '\n' || (h.tail[2] == '\r' && h.tail[1] == '\n'))
		h.tail = [3]byte{h.tail[1], h.tail[2], b}
		if end {
			if interim(h.line) {
				h.line, h.tail = h.line[:0], [3]byte{}
				continue
			}
			h.done = true
			continue
		}
		if (b < 0x20 && b != '\r' && b != '\n' && b != '\t') || b == 0x7f {
			p[i] = ' '
		}
	}
	return n, err
}

// interim reports whether a status line is a 1xx response other than 101,
// after which another header block follows.
func interim(statusLine []byte) bool {
	_, code, ok := bytes.Cut(statusLine, []byte(" "))
	return ok && len(code) >= 3 && code[0] == '1' && string(code[:3]) != "101"
}
