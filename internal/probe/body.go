package probe

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// zstdMaxWindow bounds the decoder's memory per response; RFC 8878 asks
// HTTP decoders to support at least 8 MiB.
const zstdMaxWindow = 8 << 20

// bodyResult describes how a response body was read.
type bodyResult struct {
	truncated   bool   // stopped at the size limit
	readErr     error  // error after at least the headers were received
	encoding    string // content-encoding that was decoded ("" = identity)
	undecodable bool   // encoding we cannot decode (body kept as received)
	wireBytes   int64  // bytes consumed from the connection
}

// countingReader counts bytes read from the connection, before decoding.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readBody reads at most limit decoded bytes into buf (which is reset).
//
// Decompression is done here rather than by net/http so that a server that
// labels a plain body as gzip (common with misconfigured proxies) is handled
// by sniffing magic bytes instead of failing and re-sending the request, and
// so the limit applies to decoded bytes (decompression-bomb safe).
func readBody(body io.Reader, contentEncoding string, limit int64, buf *bytes.Buffer) bodyResult {
	buf.Reset()
	cr := &countingReader{r: body}
	br := bufio.NewReaderSize(cr, 4096)
	var res bodyResult

	var r io.Reader = br
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	switch enc {
	case "", "identity":
	case "gzip", "x-gzip":
		if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
			if zr, err := gzip.NewReader(br); err == nil {
				zr.Multistream(true)
				r, res.encoding = zr, "gzip"
			}
		}
	case "deflate":
		if hdr, _ := br.Peek(2); len(hdr) == 2 && hdr[0]&0x0f == 8 && (uint16(hdr[0])<<8|uint16(hdr[1]))%31 == 0 {
			if zr, err := zlib.NewReader(br); err == nil {
				r, res.encoding = zr, "deflate"
			}
		} else if len(hdr) > 0 {
			r, res.encoding = flate.NewReader(br), "deflate"
		}
	case "br":
		// Brotli has no magic number; a plain body mislabeled "br" fails
		// to decode within its first bytes, a real stream does not.
		if peek, _ := br.Peek(4096); looksBrotli(peek) {
			r, res.encoding = brotli.NewReader(br), "br"
		}
	case "zstd":
		if magic, _ := br.Peek(4); bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
			zr, err := zstd.NewReader(br, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
				zstd.WithDecoderMaxWindow(zstdMaxWindow))
			if err == nil {
				defer zr.Close()
				r, res.encoding = zr, "zstd"
			}
		}
	default:
		// compress, multiple codings: not decoded; extraction works on raw bytes.
		res.undecodable = true
	}

	n, err := buf.ReadFrom(io.LimitReader(r, limit+1))
	if n > limit {
		buf.Truncate(int(limit))
		res.truncated = true
		err = nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		res.readErr = err
	}
	res.wireBytes = cr.n
	return res
}

// looksBrotli reports whether peek is the start of a brotli stream: it
// decodes without error, or only runs out of input.
func looksBrotli(peek []byte) bool {
	if len(peek) == 0 {
		return false
	}
	_, err := io.Copy(io.Discard, io.LimitReader(brotli.NewReader(bytes.NewReader(peek)), 1<<20))
	return err == nil || errors.Is(err, io.ErrUnexpectedEOF)
}

// drain discards up to max bytes so the connection can be reused.
func drain(body io.ReadCloser, max int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, max))
	_ = body.Close()
}
