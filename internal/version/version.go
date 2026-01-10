package version

import (
	"fmt"
	"runtime"
)

// Version information - set by goreleaser ldflags
var (
	Version     = "dev"
	Commit      = "none"
	Date        = "unknown"
	BuildSource = "source"
)

// Info returns formatted version information
func Info() string {
	return fmt.Sprintf("sbomlyze %s\n  commit: %s\n  built:  %s\n  source: %s\n  go:     %s",
		Version, Commit, Date, BuildSource, runtime.Version())
}

// Short returns just the version string
func Short() string {
	return Version
}
