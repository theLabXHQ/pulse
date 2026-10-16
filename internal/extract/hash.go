package extract

import (
	"bytes"
	"crypto/md5"  //nolint:gosec // fingerprinting, not security
	"crypto/sha1" //nolint:gosec // fingerprinting, not security
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
)

// HashAlgos lists the algorithms accepted by -hash.
var HashAlgos = []string{"md5", "sha1", "sha256", "sha512", "mmh3", "simhash"}

// ParseHashList validates a comma-separated algorithm list.
func ParseHashList(s string) ([]string, error) {
	var out []string
	for _, a := range strings.Split(s, ",") {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		ok := false
		for _, known := range HashAlgos {
			ok = ok || a == known
		}
		if !ok {
			return nil, fmt.Errorf("unsupported hash %q (supported: %s)", a, strings.Join(HashAlgos, ","))
		}
		out = append(out, a)
	}
	return out, nil
}

// Hash returns the hex digest (or decimal signed mmh3) of data.
func Hash(algo string, data []byte) string {
	switch algo {
	case "md5":
		s := md5.Sum(data) //nolint:gosec
		return hex.EncodeToString(s[:])
	case "sha1":
		s := sha1.Sum(data) //nolint:gosec
		return hex.EncodeToString(s[:])
	case "sha256":
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:])
	case "sha512":
		s := sha512.Sum512(data)
		return hex.EncodeToString(s[:])
	case "mmh3":
		return strconv.FormatInt(int64(int32(Murmur3(data, 0))), 10)
	case "simhash":
		return strconv.FormatUint(Simhash(data), 10)
	}
	return ""
}

// Murmur3 is MurmurHash3 x86 32-bit.
func Murmur3(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	tail := data[n*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// FaviconHash returns the Shodan-compatible favicon hash: signed mmh3 of the
// base64 encoding wrapped at 76 columns with a trailing newline (the output
// format of Python's base64.encodebytes).
func FaviconHash(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/76 + 1)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteByte('\n')
	return strconv.FormatInt(int64(int32(Murmur3([]byte(b.String()), 0))), 10)
}

// simhashWords splits text into the word features of
// github.com/mfonda/simhash (WordFeatureSet), so values match that library.
var simhashWords = regexp.MustCompile(`[\w']+(?:\://[\w\./]+){0,1}`)

// Simhash is a 64-bit similarity hash of data's lower-cased words (FNV-1 per
// word, bit-vector majority): near-identical pages differ in few bits.
func Simhash(data []byte) uint64 {
	var v [64]int
	h := fnv.New64()
	for _, w := range simhashWords.FindAll(bytes.ToLower(data), -1) {
		h.Reset()
		_, _ = h.Write(w)
		sum := h.Sum64()
		for i := 0; i < 64; i++ {
			if sum>>i&1 == 1 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	var f uint64
	for i := 0; i < 64; i++ {
		if v[i] >= 0 {
			f |= 1 << i
		}
	}
	return f
}

// SimhashDistance is the number of differing bits.
func SimhashDistance(a, b uint64) int { return bits.OnesCount64(a ^ b) }
