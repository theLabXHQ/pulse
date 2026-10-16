package probe

import (
	"bufio"

	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// impersonator is the RoundTripper behind -tls-impersonate: TLS with
// Chrome's ClientHello (uTLS), then HTTP/2 or HTTP/1.1 as the server picks
// via ALPN, like a browser. Some bot managers (Cloudflare among them) block
// Go's TLS fingerprint when the User-Agent claims a browser. Each request
// uses a fresh connection; plain-HTTP requests use the normal transport.
type impersonator struct {
	c     *Client
	plain http.RoundTripper
	h2    *http2.Transport
}

func newImpersonator(c *Client, plain http.RoundTripper) *impersonator {
	return &impersonator{c: c, plain: plain, h2: &http2.Transport{}}
}

func (im *impersonator) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return im.plain.RoundTrip(req)
	}
	ctx := req.Context()
	hooks := httptrace.ContextClientTrace(ctx)
	if hooks == nil {
		hooks = &httptrace.ClientTrace{}
	}
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	raw, err := im.c.dial(ctx, "tcp", addr) // net.Dialer reports connect events to the trace
	if err != nil {
		return nil, err
	}
	sni := im.c.opts.SNI
	if sni == "" {
		sni = req.URL.Hostname()
	}
	uc := utls.UClient(raw, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto) //nolint:gosec // probing must see every server
	if hooks.TLSHandshakeStart != nil {
		hooks.TLSHandshakeStart()
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	err = uc.HandshakeContext(ctx)
	st := uc.ConnectionState()
	cs := tls.ConnectionState{
		Version: st.Version, HandshakeComplete: st.HandshakeComplete, CipherSuite: st.CipherSuite,
		NegotiatedProtocol: st.NegotiatedProtocol, ServerName: st.ServerName, PeerCertificates: st.PeerCertificates,
	}
	if hooks.TLSHandshakeDone != nil {
		hooks.TLSHandshakeDone(cs, err)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	if hooks.GotConn != nil {
		hooks.GotConn(httptrace.GotConnInfo{Conn: uc})
	}
	var resp *http.Response
	if st.NegotiatedProtocol == "h2" {
		cc, err := im.h2.NewClientConn(uc)
		if err != nil {
			uc.Close()
			return nil, err
		}
		resp, err = cc.RoundTrip(req)
		if err != nil {
			uc.Close()
			return nil, err
		}
	} else {
		if err := req.Write(uc); err != nil {
			uc.Close()
			return nil, err
		}
		if hooks.WroteRequest != nil {
			hooks.WroteRequest(httptrace.WroteRequestInfo{})
		}
		resp, err = http.ReadResponse(bufio.NewReader(&firstByteReader{r: uc, hook: hooks.GotFirstResponseByte}), req)
		if err != nil {
			uc.Close()
			return nil, err
		}
	}
	resp.TLS = &cs
	resp.Body = &closeConnBody{ReadCloser: resp.Body, conn: uc}
	return resp, nil
}

// closeConnBody closes the per-request connection with the body.
type closeConnBody struct {
	io.ReadCloser
	conn net.Conn
	once sync.Once
}

func (b *closeConnBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { _ = b.conn.Close() })
	return err
}

var errImpersonateProxy = errors.New("-tls-impersonate cannot be combined with -proxy")
