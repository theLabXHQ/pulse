// Package input streams raw target lines from flags, files and stdin with a
// global line index (used for resume), without loading inputs into memory.
package input

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// MaxLineLen is the longest accepted input line.
const MaxLineLen = 64 << 10

// Line is one raw input line and its position across all sources.
type Line struct {
	Index int64
	Text  string
}

// Source lists the inputs in the order they are read.
type Source struct {
	Targets []string  // -u values (each may itself be comma separated)
	Files   []string  // -l files; "-" means stdin
	Stdin   io.Reader // read last if non-nil
	Format  string    // format of files and stdin: "" (lines) or "burp"
	// OnSkip, if set, is told about lines skipped for exceeding MaxLineLen.
	OnSkip func(source string, line int64)
}

// Formats lists the supported Source.Format values besides plain lines.
var Formats = []string{"burp"}

// Stream sends every line to out, in order, starting at index 0 but skipping
// lines with Index < skip. It returns when all sources are exhausted, ctx is
// done, or a source fails. out is not closed.
func Stream(ctx context.Context, src Source, skip int64, out chan<- Line) error {
	var idx int64
	emit := func(text string) bool {
		i := idx
		idx++
		if i < skip {
			return true
		}
		select {
		case out <- Line{Index: i, Text: text}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for _, t := range src.Targets {
		for _, part := range strings.Split(t, ",") {
			if !emit(part) {
				return ctx.Err()
			}
		}
	}
	read := func(name string, r io.Reader) error {
		if src.Format == "burp" {
			if err := readBurp(r, emit); err != nil {
				return fmt.Errorf("reading %s: %w", name, err)
			}
			return ctx.Err()
		}
		// Lines longer than MaxLineLen are skipped (and reported), not fatal:
		// one junk line must not end a long run. They still take an index,
		// so resume positions stay stable.
		br := bufio.NewReaderSize(r, 64<<10)
		for {
			line, tooLong, err := readLine(br)
			if err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("reading %s: %w", name, err)
			}
			if errors.Is(err, io.EOF) && line == "" && !tooLong {
				return nil
			}
			if tooLong {
				if src.OnSkip != nil {
					src.OnSkip(name, idx)
				}
				line = ""
			}
			if !emit(line) {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
		}
	}
	for _, f := range src.Files {
		if f == "-" {
			if src.Stdin != nil {
				if err := read("stdin", src.Stdin); err != nil {
					return err
				}
				src.Stdin = nil
			}
			continue
		}
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		err = read(f, fh)
		_ = fh.Close()
		if err != nil {
			return err
		}
	}
	if src.Stdin != nil {
		return read("stdin", src.Stdin)
	}
	return nil
}

// StdinIsPiped reports whether stdin is a pipe or file rather than a TTY.
func StdinIsPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
}

// readBurp streams the <url> of every <item> of a Burp Suite "Save items"
// XML export. Items are decoded one at a time, so large exports (requests
// and responses are embedded) do not have to fit in memory.
func readBurp(r io.Reader, emit func(string) bool) error {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	items := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if items == 0 {
				return errors.New("no Burp <item> elements found (expected a Burp Suite \"Save items\" XML export)")
			}
			return nil
		}
		if err != nil {
			return err
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "item" {
			continue
		}
		var item struct {
			URL string `xml:"url"`
		}
		if err := dec.DecodeElement(&item, &start); err != nil {
			return err
		}
		items++
		if u := strings.TrimSpace(item.URL); u != "" && !emit(u) {
			return nil
		}
	}
}

// readLine returns the next line without its line ending. A line longer
// than MaxLineLen is consumed and reported as tooLong. err is io.EOF with
// the final (possibly unterminated) line.
func readLine(br *bufio.Reader) (line string, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > MaxLineLen+2 { // +2: CRLF
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		s := strings.TrimRight(string(buf), "\r\n")
		if err != nil {
			return s, tooLong, err
		}
		return s, tooLong, nil
	}
}
