package convert

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func sampleCDXComponents() []sbom.Component {
	return []sbom.Component{
		{
			Name:      "lodash",
			Version:   "4.17.21",
			PURL:      "pkg:npm/lodash@4.17.21",
			BOMRef:    "lodash@4.17.21",
			Namespace: "utils",
			Supplier:  "Lodash Inc.",
			Licenses:  []string{"MIT"},
			CPEs: []string{
				"cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*",
				"cpe:2.3:a:lodash_project:lodash:4.17.21:*:*:*:*:*:*:*",
			},
			Hashes: map[string]string{
				"SHA-256": "abc123def456",
				"SHA-512": "789xyz",
			},
			Dependencies: []string{"dep-1"},
			Language:     "javascript",
			FoundBy:      "npm-cataloger",
			Type:         "library",
			Locations:    []string{"/node_modules/lodash/package.json"},
			ID:           "comp-lodash",
		},
		{
			Name:    "express",
			Version: "4.18.0",
			PURL:    "pkg:npm/express@4.18.0",
			BOMRef:  "express@4.18.0",
			ID:      "dep-1",
		},
	}
}

func sampleCDXInfo() sbom.SBOMInfo {
	return sbom.SBOMInfo{
		OSName:     "alpine",
		OSVersion:  "3.18",
		SourceType: "image",
		SourceName: "test-image:latest",
	}
}

func TestWriteCycloneDX_ValidStructure(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCycloneDX(&buf, sampleCDXComponents(), sampleCDXInfo())
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}
	if fmt, ok := raw["bomFormat"].(string); !ok || fmt != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", raw["bomFormat"])
	}
	if _, ok := raw["specVersion"]; !ok {
		t.Error("specVersion is missing from output")
	}
	comps, ok := raw["components"].([]interface{})
	if !ok {
		t.Fatal("components is not an array")
	}
	if len(comps) != 2 {
		t.Errorf("components length = %d, want 2", len(comps))
	}
}

func TestWriteCycloneDX_RequiredFields(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCycloneDX(&buf, nil, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}
	if v, ok := raw["bomFormat"].(string); !ok || v != "CycloneDX" {
		t.Errorf("bomFormat = %v, want \"CycloneDX\"", raw["bomFormat"])
	}
	if v, ok := raw["specVersion"].(string); !ok || v != "1.5" {
		t.Errorf("specVersion = %v, want \"1.5\"", raw["specVersion"])
	}
	if v, ok := raw["serialNumber"].(string); !ok {
		t.Error("serialNumber is missing")
	} else {
		if !strings.HasPrefix(v, "urn:uuid:") {
			t.Errorf("serialNumber = %q, want urn:uuid:... format", v)
		}
	}
	if v, ok := raw["version"].(float64); !ok || v < 1 {
		t.Errorf("version = %v, want >= 1", raw["version"])
	}
	if _, ok := raw["metadata"]; !ok {
		t.Error("metadata is missing")
	}
}

func TestWriteCycloneDX_ReParseRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCycloneDX(&buf, sampleCDXComponents(), sampleCDXInfo())
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to re-parse CycloneDX output: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("Re-parsed BOM has nil components")
	}
	if len(*bom.Components) != 2 {
		t.Errorf("Re-parsed components count = %d, want 2", len(*bom.Components))
	}
}

func TestWriteCycloneDX_ComponentFields(t *testing.T) {
	var buf bytes.Buffer
	comps := sampleCDXComponents()
	err := WriteCycloneDX(&buf, comps, sampleCDXInfo())
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("No components in output")
	}

	c := (*bom.Components)[0]
	if c.Name != "lodash" {
		t.Errorf("Name = %q, want %q", c.Name, "lodash")
	}
	if c.Version != "4.17.21" {
		t.Errorf("Version = %q, want %q", c.Version, "4.17.21")
	}
	if c.PackageURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("PackageURL = %q, want %q", c.PackageURL, "pkg:npm/lodash@4.17.21")
	}
	if c.BOMRef != "lodash@4.17.21" {
		t.Errorf("BOMRef = %q, want %q", c.BOMRef, "lodash@4.17.21")
	}
	if c.Group != "utils" {
		t.Errorf("Group = %q, want %q", c.Group, "utils")
	}
	if c.Type != cdx.ComponentTypeLibrary {
		t.Errorf("Type = %v, want %v", c.Type, cdx.ComponentTypeLibrary)
	}
}

func TestWriteCycloneDX_Licenses(t *testing.T) {
	var buf bytes.Buffer
	comps := sampleCDXComponents()
	err := WriteCycloneDX(&buf, comps, sampleCDXInfo())
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	c := (*bom.Components)[0]
	if c.Licenses == nil {
		t.Fatal("Licenses is nil")
	}
	if len(*c.Licenses) != 1 {
		t.Fatalf("Licenses count = %d, want 1", len(*c.Licenses))
	}
	lic := (*c.Licenses)[0]
	if lic.License == nil || lic.License.ID != "MIT" {
		t.Errorf("License ID = %v, want MIT", lic)
	}
}

func TestWriteCycloneDX_Hashes(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:    "test",
			Version: "1.0",
			Hashes: map[string]string{
				"SHA256": "abcdef1234567890",
			},
		},
	}
	err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	c := (*bom.Components)[0]
	if c.Hashes == nil || len(*c.Hashes) == 0 {
		t.Fatal("Hashes is empty")
	}

	h := (*c.Hashes)[0]
	if h.Algorithm != cdx.HashAlgoSHA256 {
		t.Errorf("Hash algorithm = %q, want %q", h.Algorithm, cdx.HashAlgoSHA256)
	}
	if h.Value != "abcdef1234567890" {
		t.Errorf("Hash value = %q, want %q", h.Value, "abcdef1234567890")
	}
}

func TestWriteCycloneDX_CPEs(t *testing.T) {
	var buf bytes.Buffer
	comps := sampleCDXComponents()
	err := WriteCycloneDX(&buf, comps, sampleCDXInfo())
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	c := (*bom.Components)[0]
	if c.CPE != "cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*" {
		t.Errorf("CPE field = %q, want first CPE", c.CPE)
	}
	if c.Properties == nil {
		t.Fatal("Properties is nil, expected extra CPEs as properties")
	}
	foundExtraCPE := false
	for _, p := range *c.Properties {
		if p.Name == "sbomlyze:cpe" && p.Value == "cpe:2.3:a:lodash_project:lodash:4.17.21:*:*:*:*:*:*:*" {
			foundExtraCPE = true
		}
	}
	if !foundExtraCPE {
		t.Error("Extra CPE not found in properties")
	}
}

func TestWriteCycloneDX_Supplier(t *testing.T) {
	var buf bytes.Buffer
	comps := sampleCDXComponents()
	err := WriteCycloneDX(&buf, comps, sampleCDXInfo())
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	c := (*bom.Components)[0]
	if c.Supplier == nil {
		t.Fatal("Supplier is nil")
	}
	if c.Supplier.Name != "Lodash Inc." {
		t.Errorf("Supplier name = %q, want %q", c.Supplier.Name, "Lodash Inc.")
	}
}

func TestWriteCycloneDX_Dependencies(t *testing.T) {
	var buf bytes.Buffer
	comps := sampleCDXComponents()
	err := WriteCycloneDX(&buf, comps, sampleCDXInfo())
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if bom.Dependencies == nil {
		t.Fatal("Dependencies is nil")
	}
	deps := *bom.Dependencies
	if len(deps) < 2 {
		t.Fatalf("Dependencies count = %d, want at least 2", len(deps))
	}
	found := false
	for _, dep := range deps {
		if dep.Ref == "lodash@4.17.21" && dep.Dependencies != nil {
			for _, d := range *dep.Dependencies {
				if d == "express@4.18.0" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("Expected lodash to depend on express in dependency graph")
	}
}

func TestWriteCycloneDX_SyftProperties(t *testing.T) {
	var buf bytes.Buffer
	comps := sampleCDXComponents()
	err := WriteCycloneDX(&buf, comps, sampleCDXInfo())
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	c := (*bom.Components)[0]
	if c.Properties == nil {
		t.Fatal("Properties is nil")
	}

	propMap := make(map[string][]string)
	for _, p := range *c.Properties {
		propMap[p.Name] = append(propMap[p.Name], p.Value)
	}
	if vals, ok := propMap["sbomlyze:language"]; !ok || vals[0] != "javascript" {
		t.Errorf("sbomlyze:language not found or wrong value, got %v", propMap["sbomlyze:language"])
	}
	if vals, ok := propMap["sbomlyze:foundBy"]; !ok || vals[0] != "npm-cataloger" {
		t.Errorf("sbomlyze:foundBy not found or wrong value, got %v", propMap["sbomlyze:foundBy"])
	}
	if vals, ok := propMap["sbomlyze:location"]; !ok || vals[0] != "/node_modules/lodash/package.json" {
		t.Errorf("sbomlyze:location not found or wrong value, got %v", propMap["sbomlyze:location"])
	}
}

func TestWriteCycloneDX_Metadata(t *testing.T) {
	var buf bytes.Buffer
	info := sampleCDXInfo()
	err := WriteCycloneDX(&buf, sampleCDXComponents(), info)
	if err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if bom.Metadata == nil {
		t.Fatal("Metadata is nil")
	}
	if bom.Metadata.Timestamp == "" {
		t.Error("Metadata timestamp is empty")
	}
	if bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil {
		t.Fatal("Metadata tools/components is nil")
	}
	tools := *bom.Metadata.Tools.Components
	if len(tools) == 0 {
		t.Fatal("No tools in metadata")
	}
	if tools[0].Name != "sbomlyze" {
		t.Errorf("Tool name = %q, want %q", tools[0].Name, "sbomlyze")
	}
	if bom.Metadata.Properties == nil {
		t.Fatal("Metadata properties is nil")
	}
	propMap := make(map[string]string)
	for _, p := range *bom.Metadata.Properties {
		propMap[p.Name] = p.Value
	}
	if propMap["sbomlyze:os:name"] != "alpine" {
		t.Errorf("os:name = %q, want %q", propMap["sbomlyze:os:name"], "alpine")
	}
	if propMap["sbomlyze:os:version"] != "3.18" {
		t.Errorf("os:version = %q, want %q", propMap["sbomlyze:os:version"], "3.18")
	}
	if propMap["sbomlyze:source:type"] != "image" {
		t.Errorf("source:type = %q, want %q", propMap["sbomlyze:source:type"], "image")
	}
	if propMap["sbomlyze:source:name"] != "test-image:latest" {
		t.Errorf("source:name = %q, want %q", propMap["sbomlyze:source:name"], "test-image:latest")
	}
}

func TestWriteCycloneDX_EmptyInput(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCycloneDX(&buf, nil, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteCycloneDX with nil components failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode empty BOM: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.Components != nil && len(*bom.Components) > 0 {
		t.Errorf("Expected zero components, got %d", len(*bom.Components))
	}
}

func TestWriteCycloneDX_ComponentTypeMapping(t *testing.T) {
	tests := []struct {
		inputType string
		wantType  cdx.ComponentType
	}{
		{"library", cdx.ComponentTypeLibrary},
		{"application", cdx.ComponentTypeApplication},
		{"framework", cdx.ComponentTypeFramework},
		{"container", cdx.ComponentTypeContainer},
		{"operating-system", cdx.ComponentTypeOS},
		{"device", cdx.ComponentTypeDevice},
		{"firmware", cdx.ComponentTypeFirmware},
		{"file", cdx.ComponentTypeFile},
		{"", cdx.ComponentTypeLibrary},          // default
		{"unknown-type", cdx.ComponentTypeLibrary}, // fallback
	}

	for _, tt := range tests {
		t.Run("type_"+tt.inputType, func(t *testing.T) {
			var buf bytes.Buffer
			comps := []sbom.Component{
				{Name: "test", Version: "1.0", Type: tt.inputType},
			}
			err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{})
			if err != nil {
				t.Fatalf("WriteCycloneDX failed: %v", err)
			}

			var bom cdx.BOM
			decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
			if err := decoder.Decode(&bom); err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			c := (*bom.Components)[0]
			if c.Type != tt.wantType {
				t.Errorf("Component type = %v, want %v", c.Type, tt.wantType)
			}
		})
	}
}

func TestWriteCycloneDX_HashAlgorithmNormalization(t *testing.T) {
	tests := []struct {
		input string
		want  cdx.HashAlgorithm
	}{
		{"SHA256", cdx.HashAlgoSHA256},
		{"SHA-256", cdx.HashAlgoSHA256},
		{"SHA512", cdx.HashAlgoSHA512},
		{"SHA-512", cdx.HashAlgoSHA512},
		{"SHA1", cdx.HashAlgoSHA1},
		{"SHA-1", cdx.HashAlgoSHA1},
		{"MD5", cdx.HashAlgoMD5},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var buf bytes.Buffer
			comps := []sbom.Component{
				{Name: "test", Version: "1.0", Hashes: map[string]string{tt.input: "deadbeef"}},
			}
			if err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
				t.Fatalf("WriteCycloneDX failed: %v", err)
			}

			var bom cdx.BOM
			decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
			if err := decoder.Decode(&bom); err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			h := (*(*bom.Components)[0].Hashes)[0]
			if h.Algorithm != tt.want {
				t.Errorf("hash algorithm = %q, want %q", h.Algorithm, tt.want)
			}
			if h.Value != "deadbeef" {
				t.Errorf("hash value = %q, want %q", h.Value, "deadbeef")
			}
		})
	}
}

func TestWriteCycloneDX_MultipleHashes(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:    "test",
			Version: "1.0",
			Hashes: map[string]string{
				"SHA256": "abc123",
				"MD5":    "def456",
				"SHA512": "789xyz",
			},
		},
	}
	if err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	hashes := *(*bom.Components)[0].Hashes
	if len(hashes) != 3 {
		t.Errorf("hash count = %d, want 3", len(hashes))
	}

	hashMap := make(map[cdx.HashAlgorithm]string)
	for _, h := range hashes {
		hashMap[h.Algorithm] = h.Value
	}
	if hashMap[cdx.HashAlgoSHA256] != "abc123" {
		t.Errorf("SHA-256 value = %q, want abc123", hashMap[cdx.HashAlgoSHA256])
	}
	if hashMap[cdx.HashAlgoMD5] != "def456" {
		t.Errorf("MD5 value = %q, want def456", hashMap[cdx.HashAlgoMD5])
	}
	if hashMap[cdx.HashAlgoSHA512] != "789xyz" {
		t.Errorf("SHA-512 value = %q, want 789xyz", hashMap[cdx.HashAlgoSHA512])
	}
}

func TestWriteCycloneDX_MultipleLicenses(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:     "test",
			Version:  "1.0",
			Licenses: []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
	}
	if err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	lics := *(*bom.Components)[0].Licenses
	if len(lics) != 3 {
		t.Fatalf("license count = %d, want 3", len(lics))
	}

	wantIDs := []string{"MIT", "Apache-2.0", "BSD-3-Clause"}
	for i, lic := range lics {
		if lic.License == nil || lic.License.ID != wantIDs[i] {
			t.Errorf("license[%d].ID = %v, want %q", i, lic.License, wantIDs[i])
		}
	}
}

func TestWriteCycloneDX_NoLicensesField(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{Name: "test", Version: "1.0"},
	}
	if err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	c := (*bom.Components)[0]
	if c.Licenses != nil && len(*c.Licenses) > 0 {
		t.Errorf("expected nil/empty licenses for component with no licenses, got %d", len(*c.Licenses))
	}
}

func TestWriteCycloneDX_NoCPEsField(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{Name: "test", Version: "1.0"},
	}
	if err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	c := (*bom.Components)[0]
	if c.CPE != "" {
		t.Errorf("expected empty CPE for component with no CPEs, got %q", c.CPE)
	}
}

func TestWriteCycloneDX_NoSupplierField(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{Name: "test", Version: "1.0"},
	}
	if err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	c := (*bom.Components)[0]
	if c.Supplier != nil {
		t.Errorf("expected nil supplier for component with no supplier, got %v", c.Supplier)
	}
}

func TestWriteCycloneDX_BOMRefGeneration(t *testing.T) {
	tests := []struct {
		name    string
		comp    sbom.Component
		wantRef string
	}{
		{
			name:    "uses BOMRef when set",
			comp:    sbom.Component{Name: "pkg", BOMRef: "custom-ref"},
			wantRef: "custom-ref",
		},
		{
			name:    "falls back to PURL",
			comp:    sbom.Component{Name: "pkg", PURL: "pkg:npm/pkg@1.0"},
			wantRef: "pkg:npm/pkg@1.0",
		},
		{
			name:    "falls back to name@version",
			comp:    sbom.Component{Name: "pkg", Version: "1.0"},
			wantRef: "pkg@1.0",
		},
		{
			name:    "falls back to name only",
			comp:    sbom.Component{Name: "pkg"},
			wantRef: "pkg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteCycloneDX(&buf, []sbom.Component{tt.comp}, sbom.SBOMInfo{})
			if err != nil {
				t.Fatalf("WriteCycloneDX failed: %v", err)
			}

			var bom cdx.BOM
			decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
			if err := decoder.Decode(&bom); err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			c := (*bom.Components)[0]
			if c.BOMRef != tt.wantRef {
				t.Errorf("BOMRef = %q, want %q", c.BOMRef, tt.wantRef)
			}
		})
	}
}
