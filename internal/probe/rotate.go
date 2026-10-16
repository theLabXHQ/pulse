package probe

import (
	"net/http"
	"sync/atomic"
)

// rotateEvery bounds the per-host bookkeeping a no-keep-alive transport
// accumulates (see rotatingTransport).
const rotateEvery = 1024

// rotatingTransport replaces its http.Transport with a fresh clone every
// n requests. With a negative MaxIdleConnsPerHost, net/http queues each
// request in a per-host wait list that only returning an idle connection
// would clear, so a transport leaks an entry (~500 B) for every distinct
// host it ever saw. A retired transport holds no idle connections; it is
// garbage once its in-flight requests finish, wait lists included.
type rotatingTransport struct {
	every uint64
	n     atomic.Uint64
	cur   atomic.Pointer[http.Transport]
}

func newRotatingTransport(t *http.Transport, every uint64) *rotatingTransport {
	r := &rotatingTransport{every: every}
	r.cur.Store(t)
	return r
}

func (r *rotatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t := r.cur.Load()
	if r.n.Add(1)%r.every == 0 {
		r.cur.Store(t.Clone())
	}
	return t.RoundTrip(req)
}

// CloseIdleConnections closes the current transport's idle connections;
// retired ones have none.
func (r *rotatingTransport) CloseIdleConnections() { r.cur.Load().CloseIdleConnections() }
