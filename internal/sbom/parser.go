package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ParseFile parses an SBOM file.
func ParseFile(path string) ([]Component, error) {
	comps, _, err := ParseFileWithInfo(path)
	return comps, err
}

// ParseFileWithInfo parses an SBOM file with metadata.
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
		return comps, SBOMInfo{}, err
	}
	if IsSyft(data) {
		return ParseSyftWithInfo(data)
	}
	return nil, SBOMInfo{}, fmt.Errorf("unknown SBOM format")
}

// decodeTopLevelKeys extracts top-level JSON keys.
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

// IsCycloneDX detects CycloneDX JSON format.
func IsCycloneDX(data []byte) bool {
	keys := decodeTopLevelKeys(data)
	if keys == nil {
		return false
	}
	if v, ok := keys["bomFormat"].(string); ok && v == "CycloneDX" {
		return true
	}
	if v, ok := keys["$schema"].(string); ok && strings.Contains(strings.ToLower(v), "cyclonedx") {
		return true
	}
	return false
}

// IsSPDX detects SPDX JSON format.
func IsSPDX(data []byte) bool {
	keys := decodeTopLevelKeys(data)
	if keys == nil {
		return false
	}
	if v, ok := keys["spdxVersion"].(string); ok && strings.HasPrefix(v, "SPDX-") {
		return true
	}
	return false
}

// IsSyft detects Syft JSON format.
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
