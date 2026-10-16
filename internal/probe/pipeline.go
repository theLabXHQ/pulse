package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/theLabXHQ/pulse/internal/target"
)

// pipelineProbes is how many requests -pipeline sends back to back.
const pipelineProbes = 3

// Pipeline reports whether the server answers HTTP/1.1 requests pipelined
// on one connection: pipelineProbes requests are written at once and at
// least two complete responses must come back. It uses
// the client's dialer (DNS cache, -deny policy, timeout), CRLF line endings
// and real response parsing. It returns false when a proxy is configured.
func (c *Client) Pipeline(ctx context.Context, scheme, host string, port int) bool {
	if c.Proxied() {
		return false
	}
	if port == 0 {
		port = target.DefaultPort(scheme)
	}
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	conn, err := c.dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if scheme == target.SchemeHTTPS {
		cfg := c.transport.TLSClientConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		cfg.NextProtos = []string{"http/1.1"}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return false
		}
		conn = tc
	}

	hostHeader := host
	if port != target.DefaultPort(scheme) {
		hostHeader = net.JoinHostPort(host, strconv.Itoa(port))
	}
	req := "GET / HTTP/1.1\r\nHost: " + hostHeader + "\r\nUser-Agent: " + c.opts.UserAgent +
		"\r\nAccept: */*\r\n\r\n"
	if _, err := io.WriteString(conn, strings.Repeat(req, pipelineProbes)); err != nil {
		return false
	}
	br := bufio.NewReader(conn)
	got := 0
	for i := 0; i < pipelineProbes; i++ {
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
		if err != nil {
			break
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.ProtoMajor == 1 {
			got++
		}
		if resp.Close { // the server ends the connection after this one
			break
		}
	}
	return got >= 2
}
