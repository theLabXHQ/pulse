package version

import (
	"runtime/debug"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	for _, c := range []struct {
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.1"}}, true, "0.1.1"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
		{&debug.BuildInfo{}, true, "dev"},
		{nil, false, "dev"},
	} {
		if got := fromBuildInfo(c.bi, c.ok); got != c.want {
			t.Errorf("fromBuildInfo(%+v) = %q, want %q", c.bi, got, c.want)
		}
	}
}
