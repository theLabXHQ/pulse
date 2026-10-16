package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

// Format selects the serialization.
type Format int

const (
	FormatPlain Format = iota
	FormatJSONL
	FormatCSV
)

// TextFields selects which bracketed fields text output prints.
type TextFields struct {
	Probe, StatusCode, ContentLength, ContentType, Location, Title, WebServer bool
	IP, Tech, ResponseTime, Favicon, Hash, Lines, Words, Method, HTTPVersion  bool
	TLS, CDN, ASN, VHost, Pipeline, CNAME, Extracts, BodyPreview              bool
}

// Config configures a Writer.
type Config struct {
	Format Format
	Fields TextFields
	Color  bool      // colorize text on Stdout only
	Stdout io.Writer // nil disables stdout
	File   io.Writer // optional; gets the same records, never colored
	// OnError is called once if writing fails (e.g. a closed pipe); the writer
	// then discards further results so producers are never blocked forever.
	OnError func(error)
}

// Writer serializes results from a bounded channel on one goroutine. The
// channel bound is the backpressure point: a slow consumer of stdout blocks
// workers instead of growing memory.
type Writer struct {
	cfg   Config
	in    chan *Result
	out   *bufio.Writer
	file  *bufio.Writer
	csvW  *csv.Writer
	csvF  *csv.Writer
	jsonO *json.Encoder
	jsonF *json.Encoder
	count int64
	// written holds the OnWritten callbacks of results not yet flushed.
	written []func()
}

// New creates a Writer with a queue of the given size.
func New(cfg Config, queue int) *Writer {
	w := &Writer{cfg: cfg, in: make(chan *Result, queue)}
	if cfg.Stdout != nil {
		w.out = bufio.NewWriterSize(cfg.Stdout, 64<<10)
	}
	if cfg.File != nil {
		w.file = bufio.NewWriterSize(cfg.File, 64<<10)
	}
	switch cfg.Format {
	case FormatJSONL:
		if w.out != nil {
			w.jsonO = json.NewEncoder(w.out)
			w.jsonO.SetEscapeHTML(false)
		}
		if w.file != nil {
			w.jsonF = json.NewEncoder(w.file)
			w.jsonF.SetEscapeHTML(false)
		}
	case FormatCSV:
		if w.out != nil {
			w.csvW = csv.NewWriter(w.out)
		}
		if w.file != nil {
			w.csvF = csv.NewWriter(w.file)
		}
	}
	return w
}

// In returns the channel results are sent on. Close it to finish.
func (w *Writer) In() chan<- *Result { return w.in }

// Count returns the number of results written (valid after Run returns).
func (w *Writer) Count() int64 { return w.count }

// Run consumes results until In is closed and returns the first write error.
// Output is flushed whenever the queue runs empty, so interactive pipelines
// see results immediately while bursts are written in large batches.
func (w *Writer) Run() error {
	var firstErr error
	fail := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
			if w.cfg.OnError != nil {
				w.cfg.OnError(err)
			}
		}
	}
	if w.cfg.Format == FormatCSV {
		fail(w.writeCSVHeader())
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case r, ok := <-w.in:
			if !ok {
				if firstErr == nil {
					fail(w.flush())
				}
				return firstErr
			}
			if firstErr != nil {
				continue // keep draining so producers can finish
			}
			fail(w.write(r))
			w.count++
			if r.OnWritten != nil {
				w.written = append(w.written, r.OnWritten)
			}
			if len(w.in) == 0 {
				fail(w.flush())
			}
		case <-ticker.C:
			if firstErr == nil {
				fail(w.flush())
			}
		}
	}
}

// flush writes buffered output and then confirms the flushed results.
func (w *Writer) flush() error {
	if err := w.flushBuffers(); err != nil {
		return err
	}
	for _, f := range w.written {
		f()
	}
	clear(w.written)
	w.written = w.written[:0]
	return nil
}

func (w *Writer) flushBuffers() error {
	if w.csvW != nil {
		w.csvW.Flush()
		if err := w.csvW.Error(); err != nil {
			return err
		}
	}
	if w.csvF != nil {
		w.csvF.Flush()
		if err := w.csvF.Error(); err != nil {
			return err
		}
	}
	if w.out != nil {
		if err := w.out.Flush(); err != nil {
			return err
		}
	}
	if w.file != nil {
		return w.file.Flush()
	}
	return nil
}

func (w *Writer) write(r *Result) error {
	switch w.cfg.Format {
	case FormatJSONL:
		if w.jsonO != nil {
			if err := w.jsonO.Encode(r); err != nil {
				return err
			}
		}
		if w.jsonF != nil {
			return w.jsonF.Encode(r)
		}
	case FormatCSV:
		rec := csvRecord(r)
		if w.csvW != nil {
			if err := w.csvW.Write(rec); err != nil {
				return err
			}
		}
		if w.csvF != nil {
			return w.csvF.Write(rec)
		}
	default:
		if w.out != nil {
			if _, err := w.out.WriteString(FormatText(r, w.cfg.Fields, w.cfg.Color) + "\n"); err != nil {
				return err
			}
		}
		if w.file != nil {
			_, err := w.file.WriteString(FormatText(r, w.cfg.Fields, false) + "\n")
			return err
		}
	}
	return nil
}

var csvHeader = []string{"timestamp", "input", "url", "final_url", "scheme", "host", "port", "method", "ip",
	"status_code", "content_length", "content_type", "title", "webserver", "http_version", "tls_version",
	"tech", "total_ms", "failed", "error_class", "cdn_name", "cdn_type", "as_number", "as_name"}

func (w *Writer) writeCSVHeader() error {
	if w.csvW != nil {
		if err := w.csvW.Write(csvHeader); err != nil {
			return err
		}
	}
	if w.csvF != nil {
		return w.csvF.Write(csvHeader)
	}
	return nil
}

func csvRecord(r *Result) []string {
	tlsVer, errClass, asNumber, asName := "", "", "", ""
	if r.ASN != nil {
		asNumber, asName = r.ASN.AsNumber, r.ASN.AsName
	}
	if r.TLS != nil {
		tlsVer = r.TLS.Version
	}
	if r.Error != nil {
		errClass = string(r.Error.Class)
	}
	rec := []string{r.Timestamp.Format(time.RFC3339Nano), r.Input, r.URL, r.FinalURL, r.Scheme, r.Host,
		itoaOrEmpty(r.Port), r.Method, r.IP, itoaOrEmpty(r.StatusCode), strconv.FormatInt(r.ContentLength, 10),
		r.ContentType, r.Title, r.WebServer, r.HTTPVersion, tlsVer, strings.Join(r.Tech, ";"),
		strconv.FormatFloat(r.Timing.Total, 'f', 1, 64), strconv.FormatBool(r.Failed), errClass, r.CDNName, r.CDNType, asNumber, asName}
	for i, f := range rec {
		f = clean(f)
		rec[i] = f
		// Neutralize spreadsheet formula injection from attacker-controlled fields.
		if f != "" && strings.ContainsRune("=+-@\t\r", rune(f[0])) {
			rec[i] = "'" + f
		}
	}
	return rec
}

func itoaOrEmpty(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}
