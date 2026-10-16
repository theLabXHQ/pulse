// Package asn maps IP addresses to the autonomous system announcing them.
//
// Two sources are supported:
//   - FileDB: an iptoasn.com TSV file (ip2asn-v4.tsv, ip2asn-combined.tsv,
//     optionally gzipped): offline, nothing leaves the machine;
//   - Cymru: Team Cymru's IP-to-ASN DNS service (origin.asn.cymru.com): no
//     file or API key needed, but the probed IPs are sent to Team Cymru.
//     Answers are cached per /24 (IPv4) or /48 (IPv6) and per AS.
//
// No API key is needed.
package asn

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Info describes the AS announcing an address.
type Info struct {
	Number  int
	Name    string
	Country string
	Ranges  []string // CIDRs covering the announced range
}

// Source looks up the AS for an address; (nil, nil) means not announced.
type Source interface {
	Lookup(ctx context.Context, ip netip.Addr) (*Info, error)
}

// ---- iptoasn file database ----

type v4range struct {
	start, end uint32
	as         int32 // index into FileDB.as
}

type v6range struct {
	start, end [16]byte
	as         int32
}

type asEntry struct {
	number  int
	name    string
	country string
}

// FileDB is an immutable, concurrency-safe range database.
type FileDB struct {
	v4 []v4range
	v6 []v6range
	as []asEntry
}

// LoadFile reads an iptoasn TSV file (range_start, range_end, AS_number,
// country_code, AS_description); a .gz suffix is decompressed.
func LoadFile(path string) (*FileDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		defer zr.Close()
		r = zr
	}
	return parseTSV(r)
}

func parseTSV(r io.Reader) (*FileDB, error) {
	db := &FileDB{}
	asID := map[asEntry]int32{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 5 || strings.HasPrefix(f[0], "#") {
			continue
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		num, err3 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil || err3 != nil || start.Is4() != end.Is4() || end.Less(start) {
			return nil, fmt.Errorf("asn db line %d: malformed", line)
		}
		if num == 0 {
			continue // "Not routed"
		}
		e := asEntry{number: num, country: f[3], name: f[4]}
		id, ok := asID[e]
		if !ok {
			id = int32(len(db.as))
			asID[e] = id
			db.as = append(db.as, e)
		}
		if start.Is4() {
			db.v4 = append(db.v4, v4range{u32(start), u32(end), id})
		} else {
			db.v6 = append(db.v6, v6range{start.As16(), end.As16(), id})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(db.v4)+len(db.v6) == 0 {
		return nil, fmt.Errorf("asn db: no ranges")
	}
	sort.Slice(db.v4, func(i, j int) bool { return db.v4[i].start < db.v4[j].start })
	sort.Slice(db.v6, func(i, j int) bool { return string(db.v6[i].start[:]) < string(db.v6[j].start[:]) })
	return db, nil
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// Lookup implements Source.
func (db *FileDB) Lookup(_ context.Context, ip netip.Addr) (*Info, error) {
	ip = ip.Unmap()
	if ip.Is4() {
		a := u32(ip)
		i := sort.Search(len(db.v4), func(i int) bool { return db.v4[i].start > a }) - 1
		if i >= 0 && a <= db.v4[i].end {
			r := db.v4[i]
			return db.info(r.as, rangeToCIDRs(netip.AddrFrom4(be4(r.start)), netip.AddrFrom4(be4(r.end)))), nil
		}
		return nil, nil
	}
	a := ip.As16()
	i := sort.Search(len(db.v6), func(i int) bool { return string(db.v6[i].start[:]) > string(a[:]) }) - 1
	if i >= 0 && string(a[:]) <= string(db.v6[i].end[:]) {
		r := db.v6[i]
		return db.info(r.as, rangeToCIDRs(netip.AddrFrom16(r.start), netip.AddrFrom16(r.end))), nil
	}
	return nil, nil
}

func be4(v uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b
}

func (db *FileDB) info(id int32, ranges []string) *Info {
	e := db.as[id]
	return &Info{Number: e.number, Name: e.name, Country: e.country, Ranges: ranges}
}

// rangeToCIDRs returns the minimal prefixes covering [start, end].
func rangeToCIDRs(start, end netip.Addr) []string {
	var out []string
	for len(out) < 64 {
		bitsLen := start.BitLen()
		// Largest prefix starting at start that does not pass end.
		host := trailingZeros(start)
		for ; host > 0; host-- {
			p := netip.PrefixFrom(start, bitsLen-host)
			if last(p).Compare(end) <= 0 {
				break
			}
		}
		p := netip.PrefixFrom(start, bitsLen-host)
		out = append(out, p.String())
		l := last(p)
		if l.Compare(end) >= 0 || !l.Next().IsValid() {
			break
		}
		start = l.Next()
	}
	return out
}

func trailingZeros(a netip.Addr) int {
	b := a.AsSlice()
	n := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == 0 {
			n += 8
			continue
		}
		return n + bits.TrailingZeros8(b[i])
	}
	return n
}

func last(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	host := len(b)*8 - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
