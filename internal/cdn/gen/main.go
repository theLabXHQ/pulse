// Command gen rebuilds internal/cdn/ranges.json.gz from cdncheck's
// sources_data.json (github.com/projectdiscovery/cdncheck, MIT License):
//
//	go run ./internal/cdn/gen -in $(go env GOMODCACHE)/github.com/projectdiscovery/cdncheck@v1.2.51/sources_data.json
//
// Only the IP ranges (cdn, waf, cloud) are kept; prefixes are validated and
// normalized so the runtime can trust the data.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
)

func main() {
	in := flag.String("in", "", "cdncheck sources_data.json")
	out := flag.String("out", "internal/cdn/ranges.json.gz", "output file")
	flag.Parse()
	raw, err := os.ReadFile(*in)
	if err != nil {
		log.Fatal(err)
	}
	var src map[string]json.RawMessage
	if err := json.Unmarshal(raw, &src); err != nil {
		log.Fatal(err)
	}
	dst := map[string]map[string][]string{}
	for _, kind := range []string{"cdn", "waf", "cloud"} {
		var providers map[string][]string
		if err := json.Unmarshal(src[kind], &providers); err != nil {
			log.Fatalf("%s: %v", kind, err)
		}
		dst[kind] = map[string][]string{}
		n, bad := 0, 0
		for name, cidrs := range providers {
			seen := map[netip.Prefix]bool{}
			var keep []string
			for _, c := range cidrs {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					bad++
					continue
				}
				if p.Addr().Is4In6() && p.Bits() >= 96 {
					// ::ffff:1.2.3.0/120 is 1.2.3.0/24
					p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
				}
				p = p.Masked()
				if !seen[p] {
					seen[p] = true
					keep = append(keep, p.String())
				}
			}
			sort.Strings(keep)
			dst[kind][name] = keep
			n += len(keep)
		}
		fmt.Fprintf(os.Stderr, "%s: %d providers, %d prefixes, %d invalid skipped\n", kind, len(providers), n, bad)
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err := json.NewEncoder(zw).Encode(dst); err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}
