package version

import (
	"fmt"
	"runtime"
)

// Set by goreleaser ldflags.
var (
	Version     = "dev"
	Commit      = "none"
	Date        = "unknown"
	BuildSource = "source"
)

// Info returns version info.
func Info() string {
	return fmt.Sprintf("sbomlyze %s\n  commit: %s\n  built:  %s\n  source: %s\n  go:     %s",
		Version, Commit, Date, BuildSource, runtime.Version())
}

func Short() string {
	return Version
}
