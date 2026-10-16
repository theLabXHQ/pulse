package probe

import (
	"bytes"
	"net/http"
)

// challengeMarkers appear in bot-manager block and challenge pages.
var challengeMarkers = [][]byte{
	[]byte("Just a moment..."), []byte("Attention Required!"), []byte("cf-chl"), // Cloudflare
	[]byte("Checking your browser"), []byte("Pardon Our Interruption"), []byte("_Incapsula_Resource"),
	[]byte("Client Challenge"), []byte("Your request has been blocked"), []byte("captcha-delivery.com"), // DataDome
	[]byte("Access Denied"), []byte("Request blocked"),
}

// looksBlocked reports whether r is probably a bot manager's block or
// challenge rather than the site itself. Only then does -tls-impersonate
// retry with a browser TLS fingerprint.
func looksBlocked(r *Response) bool {
	switch r.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	}
	if r.Header.Get("Cf-Mitigated") != "" {
		return true
	}
	head := r.Body
	if len(head) > 16<<10 {
		head = head[:16<<10]
	}
	for _, m := range challengeMarkers {
		if bytes.Contains(head, m) {
			return true
		}
	}
	return false
}
