package sbom

import (
	"fmt"
	"os"
	"strings"
)

// ParseFile reads an SBOM file and returns normalized components
func ParseFile(path string) ([]Component, error) {
	comps, _, err := ParseFileWithInfo(path)
	return comps, err
}

// ParseFileWithInfo reads an SBOM file and returns normalized components along with SBOM metadata
func ParseFileWithInfo(path string) ([]Component, SBOMInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, SBOMInfo{}, err
	}

	if IsCycloneDX(data) {
		return ParseCycloneDXWithInfo(data)
	}
	if IsSPDX(data) {
		comps, err := ParseSPDX(path)
		return comps, SBOMInfo{}, err // SPDX doesn't typically have OS info
	}
	if IsSyft(data) {
		return ParseSyftWithInfo(data)
	}
	return nil, SBOMInfo{}, fmt.Errorf("unknown SBOM format")
}

// IsSyft returns true if data looks like Syft JSON format
func IsSyft(data []byte) bool {
	return strings.Contains(string(data), "\"artifacts\"")
}

// IsCycloneDX returns true if data looks like CycloneDX JSON format
func IsCycloneDX(data []byte) bool {
	return strings.Contains(string(data), "\"bomFormat\"") ||
		(strings.Contains(string(data), "\"$schema\"") && strings.Contains(string(data), "cyclonedx"))
}

// IsSPDX returns true if data looks like SPDX JSON format
func IsSPDX(data []byte) bool {
	return strings.Contains(string(data), "\"spdxVersion\"") || strings.Contains(string(data), "\"SPDXID\"")
}
