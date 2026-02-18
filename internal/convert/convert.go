package convert

import (
	"fmt"
	"io"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

type Format int

const (
	FormatCycloneDX Format = iota
	FormatSPDX
	FormatSyft
)

func (f Format) String() string {
	switch f {
	case FormatCycloneDX:
		return "cyclonedx"
	case FormatSPDX:
		return "spdx"
	case FormatSyft:
		return "syft"
	default:
		return "unknown"
	}
}

func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "cyclonedx", "cdx":
		return FormatCycloneDX, nil
	case "spdx":
		return FormatSPDX, nil
	case "syft":
		return FormatSyft, nil
	default:
		return 0, fmt.Errorf("unknown format %q: supported formats are cyclonedx (cdx), spdx, syft", s)
	}
}

func Convert(w io.Writer, comps []sbom.Component, info sbom.SBOMInfo, target Format) error {
	switch target {
	case FormatCycloneDX:
		return WriteCycloneDX(w, comps, info)
	case FormatSPDX:
		return WriteSPDX(w, comps, info)
	case FormatSyft:
		return WriteSyft(w, comps, info)
	default:
		return fmt.Errorf("unsupported target format: %d", target)
	}
}
