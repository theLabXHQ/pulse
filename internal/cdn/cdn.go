// Package cdn tells whether an IP belongs to a CDN, WAF or cloud provider,
// using the IP ranges published with ProjectDiscovery's cdncheck (MIT
// License; see NOTICE). It is offline: no DNS or HTTP requests are made.
//
// Differences from cdncheck:
//   - deterministic: when ranges of several providers overlap, the most
//     specific prefix wins (ties: provider name order); cdncheck returns
//     whichever provider its map iteration reaches first;
//   - the data is decoded on first use, not at program start;
//   - a lookup is a few binary searches, without string conversions.
//
// As in cdncheck, the kinds are checked in order cdn, waf, cloud.
package cdn

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sort"
	"sync"
)

//go:generate go run ./gen -in $GOMODCACHE/github.com/projectdiscovery/cdncheck@v1.2.51/sources_data.json -out ranges.json.gz

//go:embed ranges.json.gz
var rangesGz []byte

// Kinds in lookup order.
var Kinds = []string{"cdn", "waf", "cloud"}

// Match is a provider an address belongs to.
type Match struct {
	Name string // provider, e.g. "cloudflare"
	Type string // "cdn", "waf" or "cloud"
}

type v4entry struct {
	addr uint32
	prov uint16
}

type v6entry struct {
	hi, lo uint64
	prov   uint16
}

// table holds one kind's prefixes, grouped by prefix length (longest first)
// and sorted by address within a group.
type table struct {
	v4len []int
	v4    [][]v4entry
	v6len []int
	v6    [][]v6entry
}

// DB is an immutable, concurrency-safe range database.
type DB struct {
	names  []string
	tables []table // parallel to Kinds
}

var (
	loadOnce sync.Once
	loaded   *DB
	loadErr  error
)

// Default returns the embedded database, decoding it on first use.
func Default() (*DB, error) {
	loadOnce.Do(func() { loaded, loadErr = decode(rangesGz) })
	return loaded, loadErr
}

func decode(gz []byte) (*DB, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("cdn: %w", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("cdn: %w", err)
	}
	var data map[string]map[string][]string
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("cdn: %w", err)
	}
	return build(data)
}

// New builds a database from kind -> provider -> CIDRs, e.g. for tests or
// custom range lists.
func New(data map[string]map[string][]string) (*DB, error) { return build(data) }

// build indexes kind -> provider -> CIDRs.
func build(data map[string]map[string][]string) (*DB, error) {
	db := &DB{}
	nameID := map[string]uint16{}
	var all []string
	for _, kind := range Kinds {
		for name := range data[kind] {
			all = append(all, name)
		}
	}
	sort.Strings(all)
	for _, n := range slices.Compact(all) {
		nameID[n] = uint16(len(db.names))
		db.names = append(db.names, n)
	}

	for _, kind := range Kinds {
		v4 := map[int][]v4entry{}
		v6 := map[int][]v6entry{}
		for name, cidrs := range data[kind] {
			id := nameID[name]
			for _, c := range cidrs {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					return nil, fmt.Errorf("cdn: %s/%s: %w", kind, name, err)
				}
				p = p.Masked()
				if p.Addr().Is4() {
					a := p.Addr().As4()
					v4[p.Bits()] = append(v4[p.Bits()], v4entry{binary.BigEndian.Uint32(a[:]), id})
				} else {
					a := p.Addr().As16()
					v6[p.Bits()] = append(v6[p.Bits()], v6entry{binary.BigEndian.Uint64(a[:8]), binary.BigEndian.Uint64(a[8:]), id})
				}
			}
		}
		var t table
		for _, l := range lengthsDesc(v4) {
			es := v4[l]
			// Same prefix in several providers: lowest id (name order) wins.
			slices.SortFunc(es, func(a, b v4entry) int {
				if a.addr != b.addr {
					return cmp(a.addr, b.addr)
				}
				return int(a.prov) - int(b.prov)
			})
			es = slices.CompactFunc(es, func(a, b v4entry) bool { return a.addr == b.addr })
			t.v4len = append(t.v4len, l)
			t.v4 = append(t.v4, slices.Clip(es))
		}
		for _, l := range lengthsDesc(v6) {
			es := v6[l]
			slices.SortFunc(es, func(a, b v6entry) int {
				if a.hi != b.hi {
					return cmp(a.hi, b.hi)
				}
				if a.lo != b.lo {
					return cmp(a.lo, b.lo)
				}
				return int(a.prov) - int(b.prov)
			})
			es = slices.CompactFunc(es, func(a, b v6entry) bool { return a.hi == b.hi && a.lo == b.lo })
			t.v6len = append(t.v6len, l)
			t.v6 = append(t.v6, slices.Clip(es))
		}
		db.tables = append(db.tables, t)
	}
	return db, nil
}

func cmp[T uint32 | uint64](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func lengthsDesc[E any](m map[int][]E) []int {
	ls := make([]int, 0, len(m))
	for l := range m {
		ls = append(ls, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ls)))
	return ls
}

// Lookup returns the provider ip belongs to.
func (db *DB) Lookup(ip netip.Addr) (Match, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return Match{}, false
	}
	for k, t := range db.tables {
		if id, ok := t.lookup(ip); ok {
			return Match{Name: db.names[id], Type: Kinds[k]}, true
		}
	}
	return Match{}, false
}

func (t *table) lookup(ip netip.Addr) (uint16, bool) {
	if ip.Is4() {
		a4 := ip.As4()
		a := binary.BigEndian.Uint32(a4[:])
		for i, l := range t.v4len {
			key := a & mask32(l)
			es := t.v4[i]
			j := sort.Search(len(es), func(j int) bool { return es[j].addr >= key })
			if j < len(es) && es[j].addr == key {
				return es[j].prov, true
			}
		}
		return 0, false
	}
	a16 := ip.As16()
	hi, lo := binary.BigEndian.Uint64(a16[:8]), binary.BigEndian.Uint64(a16[8:])
	for i, l := range t.v6len {
		mh, ml := mask128(l)
		kh, kl := hi&mh, lo&ml
		es := t.v6[i]
		j := sort.Search(len(es), func(j int) bool {
			return es[j].hi > kh || (es[j].hi == kh && es[j].lo >= kl)
		})
		if j < len(es) && es[j].hi == kh && es[j].lo == kl {
			return es[j].prov, true
		}
	}
	return 0, false
}

func mask32(bits int) uint32 {
	if bits == 0 {
		return 0
	}
	return ^uint32(0) << (32 - bits)
}

func mask128(bits int) (hi, lo uint64) {
	switch {
	case bits == 0:
		return 0, 0
	case bits <= 64:
		return ^uint64(0) << (64 - bits), 0
	case bits == 128:
		return ^uint64(0), ^uint64(0)
	default:
		return ^uint64(0), ^uint64(0) << (128 - bits)
	}
}

// Providers returns the known provider names (for flag help and validation).
func (db *DB) Providers() []string { return slices.Clone(db.names) }
