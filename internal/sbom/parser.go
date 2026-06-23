package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
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
	if IsCycloneDXXML(data) {
		return ParseCycloneDXXMLWithInfo(data)
	}
	if IsSPDX(data) {
		return ParseSPDXWithInfo(path)
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

// IsCycloneDXXML detects CycloneDX XML format.
// CycloneDX XML BOMs use namespace http://cyclonedx.org/schema/bom/<version>.
func IsCycloneDXXML(data []byte) bool {
	// Quick check: must start with XML prolog or <bom root element
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	// Must look like XML (prolog or <bom element)
	if trimmed[0] != '<' {
		return false
	}
	// Decode just enough to read root element name + namespace
	dec := xml.NewDecoder(bytes.NewReader(trimmed))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if se, ok := tok.(xml.StartElement); ok {
			// Root element must be <bom>
			if se.Name.Local != "bom" {
				return false
			}
			// Must carry the CycloneDX XML namespace
			for _, attr := range se.Attr {
				if attr.Name.Space == "xmlns" && strings.HasPrefix(attr.Value, "http://cyclonedx.org/schema/bom/") {
					return true
				}
			}
			// Default namespace
			if strings.HasPrefix(se.Name.Space, "http://cyclonedx.org/schema/bom/") {
				return true
			}
			return false
		}
	}
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
