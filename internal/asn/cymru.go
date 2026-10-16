package asn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/theLabXHQ/pulse/internal/lru"
)

// TXTFunc resolves TXT records (e.g. net.Resolver.LookupTXT).
type TXTFunc func(ctx context.Context, name string) ([]string, error)

// Cymru looks addresses up through Team Cymru's DNS service:
//
//	1.0.16.104.origin.asn.cymru.com TXT "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
//	AS13335.asn.cymru.com           TXT "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
//
// See https://www.team-cymru.com/ip-asn-mapping.
type Cymru struct {
	txt     TXTFunc
	origins *lru.Cache[string, *Info] // per /24 or /48; nil value = not announced
	names   *lru.Cache[int, string]
}

// NewCymru creates a Cymru source with bounded caches.
func NewCymru(txt TXTFunc) *Cymru {
	return &Cymru{txt: txt, origins: lru.New[string, *Info](65536), names: lru.New[int, string](16384)}
}

// Lookup implements Source. The returned Info is shared; do not modify it.
func (c *Cymru) Lookup(ctx context.Context, ip netip.Addr) (*Info, error) {
	ip = ip.Unmap()
	key := cacheKey(ip)
	if info, ok := c.origins.Get(key); ok {
		return info, nil
	}
	recs, err := c.txt(ctx, originName(ip))
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			c.origins.Set(key, nil) // not announced
			return nil, nil
		}
		return nil, err
	}
	info := parseOrigin(recs)
	if info != nil {
		if name, ok := c.names.Get(info.Number); ok {
			info.Name = name
		} else if recs, err := c.txt(ctx, "AS"+strconv.Itoa(info.Number)+".asn.cymru.com"); err == nil {
			// "CLOUDFLARENET, US" -> "CLOUDFLARENET", as other sources name it.
			info.Name = strings.TrimSuffix(parseASName(recs), ", "+info.Country)
			c.names.Set(info.Number, info.Name)
		}
	}
	c.origins.Set(key, info)
	return info, nil
}

// cacheKey groups addresses by /24 (IPv4) or /48 (IPv6): routed prefixes
// are not more specific than that, so all addresses in it share the answer.
func cacheKey(ip netip.Addr) string {
	bitsLen := 24
	if ip.Is6() {
		bitsLen = 48
	}
	p, _ := ip.Prefix(bitsLen)
	return p.String()
}

func originName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	var sb strings.Builder
	const hex = "0123456789abcdef"
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0xf])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("origin6.asn.cymru.com")
	return sb.String()
}

// parseOrigin picks the most specific prefix among the answers. A record may
// list several origin ASes ("13335 209242 | ..."); the first is reported.
func parseOrigin(recs []string) *Info {
	var best *Info
	bestBits := -1
	for _, r := range recs {
		f := strings.Split(r, "|")
		if len(f) < 3 {
			continue
		}
		asns := strings.Fields(f[0])
		if len(asns) == 0 {
			continue
		}
		num, err := strconv.Atoi(asns[0])
		if err != nil || num == 0 {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(f[1]))
		if err != nil {
			continue
		}
		if p.Bits() > bestBits {
			bestBits = p.Bits()
			best = &Info{Number: num, Country: strings.TrimSpace(f[2]), Ranges: []string{p.Masked().String()}}
		}
	}
	return best
}

func parseASName(recs []string) string {
	for _, r := range recs {
		f := strings.Split(r, "|")
		if len(f) >= 5 {
			return strings.TrimSpace(f[4])
		}
	}
	return ""
}
