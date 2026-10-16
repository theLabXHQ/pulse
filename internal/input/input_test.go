package input

import (
	"context"
	"strings"
	"testing"
)

const burpExport = `<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
]>
<items burpVersion="2024.1" exportTime="Mon Oct 14 10:00:00 UZT 2026">
  <item>
    <time>Mon Oct 14 09:59:00 UZT 2026</time>
    <url><![CDATA[https://app.example.com/login?next=%2F]]></url>
    <host ip="192.0.2.10">app.example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[POST]]></method>
    <request base64="true"><![CDATA[UE9TVCAvbG9naW4gSFRUUC8xLjENCkhvc3Q6IGFwcC5leGFtcGxlLmNvbQ0KDQo=]]></request>
    <status>302</status>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMzAyIEZvdW5kDQoNCg==]]></response>
  </item>
  <item><url><![CDATA[http://api.example.com:8080/v1/users]]></url></item>
  <item><url></url></item>
</items>`

func collect(t *testing.T, src Source, skip int64) []Line {
	t.Helper()
	out := make(chan Line, 100)
	if err := Stream(context.Background(), src, skip, out); err != nil {
		t.Fatal(err)
	}
	close(out)
	var lines []Line
	for l := range out {
		lines = append(lines, l)
	}
	return lines
}

func TestBurpInput(t *testing.T) {
	lines := collect(t, Source{Stdin: strings.NewReader(burpExport), Format: "burp"}, 0)
	var got []string
	for _, l := range lines {
		got = append(got, l.Text)
	}
	if strings.Join(got, " ") != "https://app.example.com/login?next=%2F http://api.example.com:8080/v1/users" {
		t.Fatalf("got %v", got)
	}
	// Resume skips by item index like it does by line index.
	if lines := collect(t, Source{Stdin: strings.NewReader(burpExport), Format: "burp"}, 1); len(lines) != 1 || lines[0].Index != 1 {
		t.Fatalf("resume: %v", lines)
	}
}

func TestBurpInputRejectsGarbage(t *testing.T) {
	out := make(chan Line, 10)
	err := Stream(context.Background(), Source{Stdin: strings.NewReader("<items><item><url>x</item>"), Format: "burp"}, 0, out)
	if err == nil {
		t.Fatal("malformed XML must be an error")
	}
}

func TestLongLineIsSkippedNotFatal(t *testing.T) {
	long := strings.Repeat("a", MaxLineLen+10)
	in := "first\r\n" + long + "\nthird\nlast-no-newline"
	var skipped []int64
	lines := collect(t, Source{Stdin: strings.NewReader(in), OnSkip: func(_ string, i int64) { skipped = append(skipped, i) }}, 0)
	var got []string
	for _, l := range lines {
		got = append(got, l.Text)
	}
	if strings.Join(got, "|") != "first||third|last-no-newline" || len(skipped) != 1 || skipped[0] != 1 {
		t.Fatalf("got %q skipped %v", got, skipped)
	}
	if lines[2].Index != 2 {
		t.Fatalf("indexes must stay stable: %+v", lines[2])
	}
}

func TestBurpInputRejectsPlainText(t *testing.T) {
	out := make(chan Line, 10)
	err := Stream(context.Background(), Source{Stdin: strings.NewReader("example.com\nfoo.bar\n"), Format: "burp"}, 0, out)
	if err == nil || !strings.Contains(err.Error(), "no Burp <item>") {
		t.Fatalf("want a clear error, got %v", err)
	}
}
