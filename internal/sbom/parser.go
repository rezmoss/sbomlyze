package sbom

import (
	"fmt"
	"os"
	"strings"
)

// ParseFile reads an SBOM file and returns normalized components
func ParseFile(path string) ([]Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if IsCycloneDX(data) {
		return ParseCycloneDX(data)
	}
	if IsSPDX(data) {
		return ParseSPDX(path)
	}
	if IsSyft(data) {
		return ParseSyft(data)
	}
	return nil, fmt.Errorf("unknown SBOM format")
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
