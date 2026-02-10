package sbom

import (
	"encoding/json"
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

// decodeTopLevelKeys partially decodes JSON to extract top-level keys.
// String values are decoded; non-string values (arrays, objects) are kept as json.RawMessage.
func decodeTopLevelKeys(data []byte) map[string]interface{} {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil
	}
	result := make(map[string]interface{}, len(top))
	for k, v := range top {
		var s string
		if json.Unmarshal(v, &s) == nil {
			result[k] = s
		} else {
			result[k] = v // keep raw for non-string values (arrays, objects)
		}
	}
	return result
}

// IsCycloneDX returns true if data is CycloneDX JSON format.
// Checks for bomFormat="CycloneDX" (required per CycloneDX spec) or
// $schema URL containing "cyclonedx".
func IsCycloneDX(data []byte) bool {
	keys := decodeTopLevelKeys(data)
	if keys == nil {
		return false
	}
	// CycloneDX spec: bomFormat="CycloneDX" is required at root
	if v, ok := keys["bomFormat"].(string); ok && v == "CycloneDX" {
		return true
	}
	// Fallback: $schema containing "cyclonedx"
	if v, ok := keys["$schema"].(string); ok && strings.Contains(strings.ToLower(v), "cyclonedx") {
		return true
	}
	return false
}

// IsSPDX returns true if data is SPDX JSON format.
// Checks for spdxVersion starting with "SPDX-" (required per SPDX spec).
func IsSPDX(data []byte) bool {
	keys := decodeTopLevelKeys(data)
	if keys == nil {
		return false
	}
	// SPDX spec: spdxVersion="SPDX-X.Y" is required at root
	if v, ok := keys["spdxVersion"].(string); ok && strings.HasPrefix(v, "SPDX-") {
		return true
	}
	return false
}

// IsSyft returns true if data is Syft JSON format.
// Requires "artifacts" key AND at least one of source/distro/descriptor.
func IsSyft(data []byte) bool {
	keys := decodeTopLevelKeys(data)
	if keys == nil {
		return false
	}
	_, hasArtifacts := keys["artifacts"]
	_, hasSource := keys["source"]
	_, hasDistro := keys["distro"]
	_, hasDescriptor := keys["descriptor"]
	return hasArtifacts && (hasSource || hasDistro || hasDescriptor)
}
