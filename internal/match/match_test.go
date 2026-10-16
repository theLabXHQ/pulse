package match

import "testing"

func TestRules(t *testing.T) {
	mc, _ := ParseInts("200,301-302")
	fc, _ := ParseInts("404")
	re, _ := ParseRegexes([]string{`admin\s+panel`})
	r := &Rules{MatchCodes: mc, FilterCodes: fc, MatchRegex: re, FilterStrings: ParseStrings([]string{"Parked"})}

	ok := Input{StatusCode: 200, Body: []byte("the Admin  panel")}
	if r.Keep(ok) {
		t.Fatal("regex is case-sensitive; 'Admin  panel' should not match")
	}
	ok.Body = []byte("the admin  panel")
	if !r.Keep(ok) {
		t.Fatal("expected keep")
	}
	if r.Keep(Input{StatusCode: 302, Body: []byte("admin panel"), Headers: []byte("X: PARKED domain")}) {
		t.Fatal("filter string must be case-insensitive and cover headers")
	}
	if r.Keep(Input{StatusCode: 500, Body: []byte("admin panel")}) {
		t.Fatal("500 not in match codes")
	}
	if !(&Rules{}).Keep(Input{}) || !(&Rules{}).Empty() {
		t.Fatal("empty rules keep everything")
	}
}

func TestKeepFavicon(t *testing.T) {
	r := &Rules{MatchFavicon: ParseSet([]string{"123"}), FilterFavicon: ParseSet([]string{"-5"})}
	if !r.KeepFavicon("123") || r.KeepFavicon("") || r.KeepFavicon("-5") {
		t.Fatal("favicon rules wrong")
	}
}

func TestParseIntsErrors(t *testing.T) {
	for _, bad := range []string{"abc", "5-1", "1-200000"} {
		if _, err := ParseInts(bad); err == nil {
			t.Errorf("ParseInts(%q) should fail", bad)
		}
	}
	if m, err := ParseInts(""); err != nil || m != nil {
		t.Fatal("empty means no rule")
	}
}
