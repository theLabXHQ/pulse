package dns

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// systemConfig is the part of the system resolver configuration Pulse
// honours: resolv.conf name servers, search list and ndots, and /etc/hosts.
type systemConfig struct {
	servers []netip.AddrPort
	search  []string
	ndots   int
	hosts   map[string][]netip.Addr
}

// loadSystem reads resolv.conf and the hosts file. A missing hosts file is
// not an error; a resolv.conf without usable name servers is.
func loadSystem(resolvConf, hostsFile string) (*systemConfig, error) {
	f, err := os.Open(resolvConf)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg := &systemConfig{ndots: 1, hosts: map[string][]netip.Addr{}}
	var domain string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], ";") {
			continue
		}
		switch fields[0] {
		case "nameserver":
			ip, err := netip.ParseAddr(fields[1])
			if err == nil && len(cfg.servers) < 3 { // glibc uses at most three
				cfg.servers = append(cfg.servers, netip.AddrPortFrom(ip.Unmap().WithZone(""), 53))
			}
		case "domain":
			domain = normalizeName(fields[1])
		case "search":
			cfg.search = cfg.search[:0]
			for _, d := range fields[1:] {
				if d = normalizeName(d); d != "" {
					cfg.search = append(cfg.search, d)
				}
			}
		case "options":
			for _, o := range fields[1:] {
				if v, ok := strings.CutPrefix(o, "ndots:"); ok {
					if n, err := strconv.Atoi(v); err == nil {
						cfg.ndots = min(max(n, 0), 15)
					}
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(cfg.servers) == 0 {
		return nil, errors.New("no name servers in " + resolvConf)
	}
	if len(cfg.search) == 0 && domain != "" {
		cfg.search = []string{domain}
	}
	cfg.hosts = loadHosts(hostsFile)
	return cfg, nil
}

// loadHosts reads a hosts file; a missing or unreadable file yields an
// empty map.
func loadHosts(path string) map[string][]netip.Addr {
	hosts := map[string][]netip.Addr{}
	hf, err := os.Open(path)
	if err != nil {
		return hosts
	}
	defer hf.Close()
	hs := bufio.NewScanner(hf)
	for hs.Scan() {
		line, _, _ := strings.Cut(hs.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		for _, name := range fields[1:] {
			name = normalizeName(name)
			hosts[name] = append(hosts[name], ip.Unmap().WithZone(""))
		}
	}
	return hosts
}

func normalizeName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// systemResolver resolves like the C library would with cfg, but over
// Pulse's UDP client: /etc/hosts first, then the search list per ndots, with
// sub-second retransmits instead of resolv.conf's 5 s timeout.
type systemResolver struct {
	cfg *systemConfig
	udp *udpClient
}

// candidates lists the names to query for host, in order.
func (s *systemResolver) candidates(host string) []string {
	if len(s.cfg.search) == 0 {
		return []string{host}
	}
	out := make([]string, 0, len(s.cfg.search)+1)
	absoluteFirst := strings.Count(host, ".") >= s.cfg.ndots
	if absoluteFirst {
		out = append(out, host)
	}
	for _, d := range s.cfg.search {
		out = append(out, host+"."+d)
	}
	if !absoluteFirst {
		out = append(out, host)
	}
	return out
}

func (s *systemResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if addrs := s.cfg.hosts[host]; len(addrs) > 0 {
		return addrs, nil
	}
	var lastErr error
	for _, name := range s.candidates(host) {
		addrs, err := s.udp.LookupNetIP(ctx, name)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		var de *net.DNSError
		if err != nil && !(errors.As(err, &de) && de.IsNotFound) {
			return nil, err // timeout or server failure: do not mask it with NXDOMAIN
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	var de *net.DNSError
	if errors.As(lastErr, &de) {
		de.Name = host
	}
	return nil, lastErr
}
