package probe

import (
	"strings"
	"testing"
)

func TestParseRawRequest(t *testing.T) {
	rr, err := ParseRawRequest([]byte("POST /api/v1/login?next=/a,b HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: application/json\r\nx-custom:  yes \r\nContent-Length: 13\r\n\r\n{\"user\":\"a\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rr.Method != "POST" || rr.Path() != "/api/v1/login?next=/a,b" || rr.Host != "app.example.com" ||
		rr.Header.Get("X-Custom") != "yes" || rr.Body != "{\"user\":\"a\"}\n" {
		t.Fatalf("%+v", rr)
	}
	rr, err = ParseRawRequest([]byte("GET http://h.example:8080/x?y=1 HTTP/1.1\nAccept: */*\n\n"))
	if err != nil || rr.Host != "h.example:8080" || rr.Path() != "/x?y=1" {
		t.Fatalf("absolute URI with LF endings: %+v %v", rr, err)
	}
	for _, bad := range []string{"", "GARBAGE\n\n", "GET / HTTP/1.1\nno colon here\n\n"} {
		if _, err := ParseRawRequest([]byte(bad)); err == nil || !strings.Contains(err.Error(), "bad") {
			t.Errorf("%q: want error, got %v", bad, err)
		}
	}
}
