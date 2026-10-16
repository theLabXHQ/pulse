// Package version holds build metadata.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is set at link time by release builds
// (-ldflags "-X github.com/theLabXHQ/pulse/internal/version.Version=1.2.3").
// Otherwise it comes from the module version Go records in the binary,
// which `go install github.com/theLabXHQ/pulse/cmd/pulse@vX.Y.Z` fills in.
var Version = ""

// SchemaVersion identifies the JSONL result schema. It changes only on
// backwards-incompatible field changes; new optional fields do not bump it.
const SchemaVersion = "pulse.v1"

func init() {
	if Version == "" {
		Version = fromBuildInfo(debug.ReadBuildInfo())
	}
}

// fromBuildInfo returns the main module's version without the leading "v",
// or "dev" for a local build that has none.
func fromBuildInfo(bi *debug.BuildInfo, ok bool) string {
	if !ok || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return "dev"
	}
	return strings.TrimPrefix(bi.Main.Version, "v")
}
