package target

import (
	"fmt"
	"net/netip"
	"strings"
)

// MaxIPv6ExpansionBits limits IPv6 range expansion to 2^24 addresses; larger
// IPv6 prefixes cannot be swept meaningfully and are rejected.
const MaxIPv6ExpansionBits = 24

// IsCIDR reports whether s is a CIDR prefix (without scheme or port).
func IsCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") || strings.Contains(s, "://") {
		return false
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
}

// ExpandCIDR calls fn for every address in the prefix, in order, until fn
// returns false. It does not allocate the address list, so /8 ranges are
// streamed with constant memory.
func ExpandCIDR(s string, fn func(netip.Addr) bool) error {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	p = p.Masked()
	if p.Addr().Is6() && p.Addr().BitLen()-p.Bits() > MaxIPv6ExpansionBits {
		return fmt.Errorf("IPv6 prefix %s is too large to expand (max /%d)", s, 128-MaxIPv6ExpansionBits)
	}
	for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
		if !fn(a) {
			return nil
		}
	}
	return nil
}
