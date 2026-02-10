package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testdataPath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func TestIsCycloneDX_BomFormat(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`)
	if !IsCycloneDX(data) {
		t.Error("expected IsCycloneDX to return true for bomFormat")
	}
}

func TestIsCycloneDX_Schema(t *testing.T) {
	data := []byte(`{"$schema":"https://cyclonedx.org/schema/bom-1.4.schema.json"}`)
	if !IsCycloneDX(data) {
		t.Error("expected IsCycloneDX to return true for $schema with cyclonedx")
	}
}

func TestIsCycloneDX_Negative(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"SPDX", `{"spdxVersion":"SPDX-2.3"}`},
		{"Syft", `{"artifacts":[],"source":{}}`},
		{"Random", `{"foo":"bar"}`},
		{"Empty", `{}`},
		{"InvalidJSON", `not json`},
		{"BomFormatInValue", `{"description":"contains bomFormat keyword"}`},
		{"BomFormatWrongValue", `{"bomFormat":"NotCycloneDX"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsCycloneDX([]byte(tt.data)) {
				t.Errorf("expected IsCycloneDX to return false for %s", tt.name)
			}
		})
	}
}

func TestIsSPDX_SpdxVersion(t *testing.T) {
	data := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	if !IsSPDX(data) {
		t.Error("expected IsSPDX to return true for spdxVersion")
	}
}

func TestIsSPDX_SPDXID_Only(t *testing.T) {
	// SPDXID alone is insufficient — spdxVersion is the required root-level field per SPDX spec
	data := []byte(`{"SPDXID":"SPDXRef-DOCUMENT"}`)
	if IsSPDX(data) {
		t.Error("expected IsSPDX to return false for SPDXID without spdxVersion")
	}
}

func TestIsSPDX_WithBothFields(t *testing.T) {
	data := []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`)
	if !IsSPDX(data) {
		t.Error("expected IsSPDX to return true for spdxVersion+SPDXID")
	}
}

func TestIsSPDX_Negative(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"CycloneDX", `{"bomFormat":"CycloneDX"}`},
		{"Syft", `{"artifacts":[],"source":{}}`},
		{"Random", `{"foo":"bar"}`},
		{"InvalidJSON", `not json`},
		{"SpdxVersionInValue", `{"description":"contains spdxVersion keyword"}`},
		{"SpdxVersionWrongPrefix", `{"spdxVersion":"NotSPDX-2.3"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsSPDX([]byte(tt.data)) {
				t.Errorf("expected IsSPDX to return false for %s", tt.name)
			}
		})
	}
}

func TestIsSyft_ArtifactsWithSource(t *testing.T) {
	data := []byte(`{"artifacts":[],"source":{"type":"image"}}`)
	if !IsSyft(data) {
		t.Error("expected IsSyft to return true for artifacts+source")
	}
}

func TestIsSyft_ArtifactsWithDistro(t *testing.T) {
	data := []byte(`{"artifacts":[],"distro":{"name":"alpine"}}`)
	if !IsSyft(data) {
		t.Error("expected IsSyft to return true for artifacts+distro")
	}
}

func TestIsSyft_ArtifactsWithDescriptor(t *testing.T) {
	data := []byte(`{"artifacts":[],"descriptor":{"name":"syft"}}`)
	if !IsSyft(data) {
		t.Error("expected IsSyft to return true for artifacts+descriptor")
	}
}

func TestIsSyft_ArtifactsOnly(t *testing.T) {
	// artifacts alone is not enough — could be any format with an "artifacts" key
	data := []byte(`{"artifacts":[]}`)
	if IsSyft(data) {
		t.Error("expected IsSyft to return false for artifacts alone without source/distro/descriptor")
	}
}

func TestIsSyft_Negative(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"CycloneDX", `{"bomFormat":"CycloneDX"}`},
		{"SPDX", `{"spdxVersion":"SPDX-2.3"}`},
		{"Random", `{"foo":"bar"}`},
		{"ArtifactsOnly", `{"artifacts":[]}`},
		{"InvalidJSON", `not json`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsSyft([]byte(tt.data)) {
				t.Errorf("expected IsSyft to return false for %s", tt.name)
			}
		})
	}
}

func TestParseFile_CycloneDX(t *testing.T) {
	comps, err := ParseFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 3 {
		t.Errorf("expected 3 components, got %d", len(comps))
	}
}

func TestParseFile_SPDX(t *testing.T) {
	comps, err := ParseFile(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 2 {
		t.Errorf("expected 2 components, got %d", len(comps))
	}
}

func TestParseFile_Syft(t *testing.T) {
	comps, err := ParseFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 3 {
		t.Errorf("expected 3 components, got %d", len(comps))
	}
}

func TestParseFile_UnknownFormat(t *testing.T) {
	_, err := ParseFile(testdataPath("invalid.json"))
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if err.Error() != "unknown SBOM format" {
		t.Errorf("expected 'unknown SBOM format' error, got: %v", err)
	}
}

func TestParseFile_NonExistent(t *testing.T) {
	_, err := ParseFile("nonexistent-file-that-does-not-exist.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseFileWithInfo_CycloneDX(t *testing.T) {
	comps, info, err := ParseFileWithInfo(testdataPath("cyclonedx-with-metadata.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 2 {
		t.Errorf("expected 2 components, got %d", len(comps))
	}
	if info.OSName != "alpine" {
		t.Errorf("expected OSName=alpine, got %q", info.OSName)
	}
	if info.OSVersion != "3.19.0" {
		t.Errorf("expected OSVersion=3.19.0, got %q", info.OSVersion)
	}
}

func TestParseFileWithInfo_Syft(t *testing.T) {
	_, info, err := ParseFileWithInfo(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SourceType != "image" {
		t.Errorf("expected SourceType=image, got %q", info.SourceType)
	}
	if info.SourceName != "alpine:latest" {
		t.Errorf("expected SourceName=alpine:latest, got %q", info.SourceName)
	}
}

func TestParseFileWithInfo_SPDX(t *testing.T) {
	comps, info, err := ParseFileWithInfo(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 2 {
		t.Errorf("expected 2 components, got %d", len(comps))
	}
	// SPDX returns empty SBOMInfo
	if info.OSName != "" || info.OSVersion != "" || info.SourceType != "" {
		t.Errorf("expected empty SBOMInfo for SPDX, got %+v", info)
	}
}

func TestFormatDetectionPrecedence(t *testing.T) {
	// A file with both "bomFormat" and "artifacts" should be detected as CycloneDX
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","artifacts":[],"components":[]}`)
	if !IsCycloneDX(data) {
		t.Error("expected CycloneDX detection to take precedence")
	}
	// In ParseFileWithInfo, CycloneDX is checked first
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	comps, _, err := ParseFileWithInfo(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// CycloneDX parser should handle it (0 components since components is empty)
	if len(comps) != 0 {
		t.Errorf("expected 0 components from empty CycloneDX, got %d", len(comps))
	}
}

func TestParse_EmptyFile(t *testing.T) {
	_, err := ParseFile(testdataPath("empty.json"))
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestParse_NotJSON(t *testing.T) {
	_, err := ParseFile(testdataPath("not-json.txt"))
	if err == nil {
		t.Fatal("expected error for non-JSON file")
	}
}

func TestParse_UnicodeNames(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{"type":"library","name":"ünïcödé-pkg","version":"1.0.0","bom-ref":"unicode"}
		]
	}`)
	tmpFile, err := os.CreateTemp(t.TempDir(), "unicode-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	comps, err := ParseFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if comps[0].Name != "ünïcödé-pkg" {
		t.Errorf("expected unicode name preserved, got %q", comps[0].Name)
	}
}

func TestParse_SpecialCharsInPURL(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{"type":"library","name":"scoped-pkg","version":"1.0.0","purl":"pkg:npm/%40scope/pkg@1.0.0","bom-ref":"scoped"}
		]
	}`)
	tmpFile, err := os.CreateTemp(t.TempDir(), "purl-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	comps, err := ParseFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if comps[0].PURL != "pkg:npm/%40scope/pkg@1.0.0" {
		t.Errorf("expected PURL preserved, got %q", comps[0].PURL)
	}
}

// False positive prevention: format keywords in string values should NOT trigger detection
func TestFormatDetection_FalsePositivePrevention(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		isCDX    bool
		isSPDX   bool
		isSyft   bool
	}{
		{
			name:   "bomFormat in description value",
			data:   `{"description":"this document has bomFormat in it","type":"report"}`,
			isCDX:  false,
			isSPDX: false,
			isSyft: false,
		},
		{
			name:   "spdxVersion in description value",
			data:   `{"description":"mentions spdxVersion for context","type":"report"}`,
			isCDX:  false,
			isSPDX: false,
			isSyft: false,
		},
		{
			name:   "artifacts in description value",
			data:   `{"description":"these are artifacts from a build","type":"report"}`,
			isCDX:  false,
			isSPDX: false,
			isSyft: false,
		},
		{
			name:   "bomFormat key with wrong value",
			data:   `{"bomFormat":"NotCycloneDX","specVersion":"1.4"}`,
			isCDX:  false,
			isSPDX: false,
			isSyft: false,
		},
		{
			name:   "spdxVersion key with wrong prefix",
			data:   `{"spdxVersion":"v2.3"}`,
			isCDX:  false,
			isSPDX: false,
			isSyft: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.data)
			if got := IsCycloneDX(data); got != tt.isCDX {
				t.Errorf("IsCycloneDX = %v, want %v", got, tt.isCDX)
			}
			if got := IsSPDX(data); got != tt.isSPDX {
				t.Errorf("IsSPDX = %v, want %v", got, tt.isSPDX)
			}
			if got := IsSyft(data); got != tt.isSyft {
				t.Errorf("IsSyft = %v, want %v", got, tt.isSyft)
			}
		})
	}
}

func TestDecodeTopLevelKeys_InvalidJSON(t *testing.T) {
	result := decodeTopLevelKeys([]byte("not json"))
	if result != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestDecodeTopLevelKeys_EmptyObject(t *testing.T) {
	result := decodeTopLevelKeys([]byte("{}"))
	if result == nil {
		t.Fatal("expected non-nil for empty object")
	}
	if len(result) != 0 {
		t.Errorf("expected 0 keys, got %d", len(result))
	}
}

func TestDecodeTopLevelKeys_MixedTypes(t *testing.T) {
	data := []byte(`{"name":"test","count":42,"items":["a","b"],"nested":{"key":"val"}}`)
	result := decodeTopLevelKeys(data)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// String values should be decoded
	if v, ok := result["name"].(string); !ok || v != "test" {
		t.Errorf("expected name=test, got %v", result["name"])
	}
	// Non-string values should be kept as json.RawMessage
	if _, ok := result["count"].(json.RawMessage); !ok {
		t.Errorf("expected count to be json.RawMessage, got %T", result["count"])
	}
	if _, ok := result["items"].(json.RawMessage); !ok {
		t.Errorf("expected items to be json.RawMessage, got %T", result["items"])
	}
}
