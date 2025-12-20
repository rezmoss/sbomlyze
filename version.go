package main

import (
	"fmt"
	"runtime"
)

// Version information - set by goreleaser ldflags
var (
	version     = "dev"
	commit      = "none"
	date        = "unknown"
	buildSource = "source"
)

// VersionInfo returns formatted version information
func VersionInfo() string {
	return fmt.Sprintf("sbomlyze %s\n  commit: %s\n  built:  %s\n  source: %s\n  go:     %s",
		version, commit, date, buildSource, runtime.Version())
}

// ShortVersion returns just the version string
func ShortVersion() string {
	return version
}
