package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// udpClient is a stub resolver for explicitly configured servers. Unlike
// net.Resolver it keeps a small pool of long-lived sockets (no socket per
// query) and retransmits lost packets after a short, growing interval instead
// of the resolv.conf default of 5s: under load a single dropped UDP packet
// must not turn a live host into a timeout.
type udpClient struct {
	servers  []netip.AddrPort
	socks    []*udpSock
	next     atomic.Uint64
	firstRTO time.Duration
	// otherGrace is how long the non-preferred family may still take once
	// the preferred one has answered: a server that drops AAAA queries
	// must not add a full timeout to every new host.
	otherGrace time.Duration
	preferV6   bool
	fallback   *net.Resolver // for truncated answers (TCP)
}

type udpSock struct {
	pc      net.PacketConn
	mu      sync.Mutex
	pending map[uint16]*pendingQuery
}

type pendingQuery struct {
	q  dnsmessage.Question
	ch chan []byte
}

var errTruncated = errors.New("dns: truncated answer")

const udpSockets = 4

func newUDPClient(servers []netip.AddrPort, preferV6 bool, fallback *net.Resolver) (*udpClient, error) {
	c := &udpClient{servers: servers, firstRTO: 400 * time.Millisecond, otherGrace: 200 * time.Millisecond,
		preferV6: preferV6, fallback: fallback}
	for i := 0; i < udpSockets; i++ {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			for _, s := range c.socks {
				_ = s.pc.Close()
			}
			return nil, err
		}
		s := &udpSock{pc: pc, pending: make(map[uint16]*pendingQuery)}
		c.socks = append(c.socks, s)
		go s.readLoop(servers)
	}
	return c, nil
}

func (s *udpSock) readLoop(servers []netip.AddrPort) {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < 12 || !fromServer(from, servers) {
			continue
		}
		id := binary.BigEndian.Uint16(buf[:2])
		s.mu.Lock()
		pq := s.pending[id]
		s.mu.Unlock()
		if pq == nil {
			continue
		}
		msg := append([]byte(nil), buf[:n]...)
		if !answersQuestion(msg, pq.q) {
			continue
		}
		select {
		case pq.ch <- msg:
		default: // a duplicate answer to a retransmit
		}
	}
}

func fromServer(from net.Addr, servers []netip.AddrPort) bool {
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		return false
	}
	ap := ua.AddrPort()
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	for _, s := range servers {
		if s == ap {
			return true
		}
	}
	return false
}

func answersQuestion(msg []byte, q dnsmessage.Question) bool {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response {
		return false
	}
	got, err := p.Question()
	return err == nil && got.Type == q.Type && got.Class == q.Class &&
		strings.EqualFold(got.Name.String(), q.Name.String())
}

// register reserves a random unused ID on s. It fails only if all 65536
// IDs of the socket are in flight.
func (s *udpSock) register(q dnsmessage.Question) (uint16, *pendingQuery, error) {
	pq := &pendingQuery{q: q, ch: make(chan []byte, 1)}
	var b [2]byte
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= 1<<16 {
		return 0, nil, errors.New("dns: too many queries in flight")
	}
	for {
		_, _ = rand.Read(b[:])
		id := binary.BigEndian.Uint16(b[:])
		if _, used := s.pending[id]; !used {
			s.pending[id] = pq
			return id, pq, nil
		}
	}
}

func (s *udpSock) unregister(id uint16) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

// LookupNetIP resolves A and AAAA in parallel. It mirrors the error
// conventions of net.Resolver (*net.DNSError with IsNotFound/IsTimeout).
// An answer without addresses (NODATA) is asked of the next server too:
// a domain whose authoritative servers disagree gets one from some public
// resolvers and not from others.
func (c *udpClient) LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(fqdn(host))
	if err != nil {
		return nil, &net.DNSError{Err: "invalid name", Name: host, IsNotFound: true}
	}
	base := c.next.Add(1)
	for i := 0; ; i++ {
		addrs, noData, err := c.lookupNetIP(ctx, host, name, base+uint64(i))
		if !noData || i+1 >= len(c.servers) || ctx.Err() != nil {
			return addrs, err
		}
	}
}

// lookupNetIP is one A+AAAA lookup whose first packets go to server n.
// noData reports an answer that had no addresses and no error.
func (c *udpClient) lookupNetIP(ctx context.Context, host string, name dnsmessage.Name, n uint64) (_ []netip.Addr, noData bool, _ error) {
	type res struct {
		t     dnsmessage.Type
		addrs []netip.Addr
		err   error
	}
	preferred := dnsmessage.TypeA
	if c.preferV6 {
		preferred = dnsmessage.TypeAAAA
	}
	qctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan res, 2)
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		go func(t dnsmessage.Type) {
			a, err := c.query(qctx, dnsmessage.Question{Name: name, Type: t, Class: dnsmessage.ClassINET}, n)
			ch <- res{t, a, err}
		}(t)
	}
	var addrs []netip.Addr
	var errs []error
	var grace <-chan time.Time
collect:
	for i := 0; i < 2; i++ {
		select {
		case r := <-ch:
			addrs = append(addrs, r.addrs...)
			if r.err != nil {
				errs = append(errs, r.err)
			}
			if r.t == preferred && len(r.addrs) > 0 && i == 0 {
				t := time.NewTimer(c.otherGrace)
				defer t.Stop()
				grace = t.C
			}
		case <-grace:
			break collect // keep the preferred answer; cancel() stops the other query
		}
	}
	if len(addrs) > 0 {
		return addrs, false, nil
	}
	for _, e := range errs {
		if errors.Is(e, errTruncated) {
			a, err := c.fallback.LookupNetIP(ctx, "ip", host)
			return a, false, err
		}
	}
	if len(errs) == 0 {
		return nil, true, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	// Prefer the most informative failure, whatever order the answers came
	// in: NXDOMAIN > other (SERVFAIL, refused, ...) > timeout.
	rank := func(err error) int {
		var de *net.DNSError
		switch {
		case errors.As(err, &de) && de.IsNotFound:
			return 2
		case errors.As(err, &de) && de.IsTimeout:
			return 0
		}
		return 1
	}
	best := errs[0]
	for _, e := range errs[1:] {
		if rank(e) > rank(best) {
			best = e
		}
	}
	var de *net.DNSError
	if errors.As(best, &de) {
		de.Name = host
		return nil, false, de
	}
	return nil, false, &net.DNSError{Err: best.Error(), Name: host}
}

func fqdn(h string) string {
	if strings.HasSuffix(h, ".") {
		return h
	}
	return h + "."
}

// query resolves an A or AAAA question. An empty answer section with
// NOERROR returns (nil, nil).
func (c *udpClient) query(ctx context.Context, q dnsmessage.Question, n uint64) ([]netip.Addr, error) {
	resp, err := c.exchangeAt(ctx, q, n)
	if err != nil {
		return nil, err
	}
	return parseAnswer(resp, q)
}

func (c *udpClient) exchange(ctx context.Context, q dnsmessage.Question) ([]byte, error) {
	return c.exchangeAt(ctx, q, c.next.Add(1))
}

// exchangeAt sends q, first to server n (mod the server count), and
// retransmits with exponential backoff, rotating servers, until an answer
// arrives or ctx expires. It returns the raw answer message.
func (c *udpClient) exchangeAt(ctx context.Context, q dnsmessage.Question, n uint64) ([]byte, error) {
	s := c.socks[n%uint64(len(c.socks))]
	id, pq, err := s.register(q)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: q.Name.String(), IsTemporary: true}
	}
	defer s.unregister(id)

	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	msg, err := b.Finish()
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: q.Name.String()}
	}

	rto := c.firstRTO
	timer := time.NewTimer(0)
	defer timer.Stop()
	for attempt := uint64(0); ; attempt++ {
		select {
		case <-ctx.Done():
			return nil, &net.DNSError{Err: "i/o timeout", Name: q.Name.String(), IsTimeout: true}
		case resp := <-pq.ch:
			return resp, nil
		case <-timer.C:
			server := c.servers[(n+attempt)%uint64(len(c.servers))]
			_, _ = s.pc.WriteTo(msg, net.UDPAddrFromAddrPort(server))
			if attempt > 0 {
				rto *= 2
			}
			timer.Reset(rto)
		}
	}
}

func parseAnswer(msg []byte, q dnsmessage.Question) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, &net.DNSError{Err: "malformed answer", Name: q.Name.String()}
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, &net.DNSError{Err: "no such host", Name: q.Name.String(), IsNotFound: true}
	default:
		return nil, &net.DNSError{Err: "server misbehaving: " + h.RCode.String(), Name: q.Name.String(), IsTemporary: true}
	}
	if h.Truncated {
		return nil, errTruncated
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, &net.DNSError{Err: "malformed answer", Name: q.Name.String()}
	}
	var out []netip.Addr
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, &net.DNSError{Err: "malformed answer", Name: q.Name.String()}
		}
		switch {
		case rh.Type == dnsmessage.TypeA && q.Type == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, &net.DNSError{Err: "malformed answer", Name: q.Name.String()}
			}
			out = append(out, netip.AddrFrom4(r.A))
		case rh.Type == dnsmessage.TypeAAAA && q.Type == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, &net.DNSError{Err: "malformed answer", Name: q.Name.String()}
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default: // CNAME chain links and anything else
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{Err: "malformed answer", Name: q.Name.String()}
			}
		}
	}
	return out, nil
}

// LookupCNAME follows the CNAME chain of host (at most 8 links).
func (c *udpClient) LookupCNAME(ctx context.Context, host string) ([]string, error) {
	var chain []string
	name := host
	for i := 0; i < 8; i++ {
		n, err := dnsmessage.NewName(fqdn(name))
		if err != nil {
			return chain, nil
		}
		q := dnsmessage.Question{Name: n, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}
		target, err := c.queryCNAME(ctx, q)
		if err != nil || target == "" {
			return chain, err
		}
		chain = append(chain, target)
		name = target
	}
	return chain, nil
}

func (c *udpClient) queryCNAME(ctx context.Context, q dnsmessage.Question) (string, error) {
	resp, err := c.exchange(ctx, q)
	if err != nil {
		return "", err
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || h.RCode != dnsmessage.RCodeSuccess {
		return "", nil // NXDOMAIN and friends: no CNAME
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", nil
	}
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			return "", nil
		}
		if rh.Type == dnsmessage.TypeCNAME {
			r, err := p.CNAMEResource()
			if err != nil {
				return "", nil
			}
			return strings.TrimSuffix(strings.ToLower(r.CNAME.String()), "."), nil
		}
		if err := p.SkipAnswer(); err != nil {
			return "", nil
		}
	}
}

// LookupTXT returns the TXT strings of name, each record's strings joined
// as net.Resolver does. Truncated answers are retried over TCP.
func (c *udpClient) LookupTXT(ctx context.Context, name string) ([]string, error) {
	n, err := dnsmessage.NewName(fqdn(name))
	if err != nil {
		return nil, &net.DNSError{Err: "invalid name", Name: name, IsNotFound: true}
	}
	q := dnsmessage.Question{Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}
	resp, err := c.exchange(ctx, q)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) {
			de.Name = name
		}
		return nil, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil, &net.DNSError{Err: "malformed answer", Name: name}
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	default:
		return nil, &net.DNSError{Err: "server misbehaving: " + h.RCode.String(), Name: name, IsTemporary: true}
	}
	if h.Truncated {
		return c.fallback.LookupTXT(ctx, name)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, &net.DNSError{Err: "malformed answer", Name: name}
	}
	var out []string
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, &net.DNSError{Err: "malformed answer", Name: name}
		}
		if rh.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{Err: "malformed answer", Name: name}
			}
			continue
		}
		r, err := p.TXTResource()
		if err != nil {
			return nil, &net.DNSError{Err: "malformed answer", Name: name}
		}
		out = append(out, strings.Join(r.TXT, ""))
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return out, nil
}
