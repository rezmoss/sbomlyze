package sbom

import (
	"os"
	"testing"
)

func TestParseCycloneDX_BasicComponents(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 3 {
		t.Fatalf("expected 3 components, got %d", len(comps))
	}
	// Check lodash
	found := false
	for _, c := range comps {
		if c.Name == "lodash" {
			found = true
			if c.Version != "4.17.20" {
				t.Errorf("expected lodash version 4.17.20, got %s", c.Version)
			}
			if c.PURL != "pkg:npm/lodash@4.17.20" {
				t.Errorf("expected lodash PURL, got %s", c.PURL)
			}
			if c.BOMRef != "lodash@4.17.20" {
				t.Errorf("expected lodash BOMRef, got %s", c.BOMRef)
			}
		}
	}
	if !found {
		t.Error("expected to find lodash component")
	}
}

func TestParseCycloneDX_Licenses(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "lodash" {
			if len(c.Licenses) != 1 || c.Licenses[0] != "MIT" {
				t.Errorf("expected lodash licenses=[MIT], got %v", c.Licenses)
			}
			return
		}
	}
	t.Error("lodash not found")
}

func TestParseCycloneDX_Hashes(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "lodash" {
			if c.Hashes == nil {
				t.Fatal("expected lodash to have hashes")
			}
			if c.Hashes["SHA-256"] != "abc123def456" {
				t.Errorf("expected SHA-256=abc123def456, got %s", c.Hashes["SHA-256"])
			}
			return
		}
	}
	t.Error("lodash not found")
}

func TestParseCycloneDX_Supplier(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "mylib" {
			if c.Supplier != "Example Corp" {
				t.Errorf("expected supplier 'Example Corp', got %q", c.Supplier)
			}
			return
		}
	}
	t.Error("mylib not found")
}

func TestParseCycloneDX_Namespace(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "mylib" {
			if c.Namespace != "com.example" {
				t.Errorf("expected namespace 'com.example', got %q", c.Namespace)
			}
			return
		}
	}
	t.Error("mylib not found")
}

func TestParseCycloneDX_CPE(t *testing.T) {
	data := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.4",
		"components":[{
			"type":"library","name":"curl","version":"8.0","cpe":"cpe:2.3:a:haxx:curl:8.0:*:*:*:*:*:*:*","bom-ref":"curl"
		}]
	}`)
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if len(comps[0].CPEs) != 1 || comps[0].CPEs[0] != "cpe:2.3:a:haxx:curl:8.0:*:*:*:*:*:*:*" {
		t.Errorf("expected CPE extracted, got %v", comps[0].CPEs)
	}
}

func TestParseCycloneDX_RawJSON(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if len(c.RawJSON) == 0 {
			t.Errorf("expected RawJSON to be populated for component %s", c.Name)
		}
	}
}

func TestParseCycloneDX_IDComputed(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.ID == "" {
			t.Errorf("expected ID to be computed for component %s", c.Name)
		}
	}
	// lodash has PURL, so ID should be based on normalized PURL
	for _, c := range comps {
		if c.Name == "lodash" {
			if c.ID != "pkg:npm/lodash" {
				t.Errorf("expected ID=pkg:npm/lodash, got %s", c.ID)
			}
		}
	}
}

func TestParseCycloneDX_EmptyComponents(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-empty-components.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 0 {
		t.Errorf("expected 0 components, got %d", len(comps))
	}
}

func TestParseCycloneDX_NilComponents(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-no-components.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 0 {
		t.Errorf("expected 0 components, got %d", len(comps))
	}
}

func TestParseCycloneDX_InvalidJSON(t *testing.T) {
	_, err := ParseCycloneDX([]byte("not valid json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseCycloneDXWithInfo_MetadataOS(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.OSName != "alpine" {
		t.Errorf("expected OSName=alpine, got %q", info.OSName)
	}
	if info.OSVersion != "3.19.0" {
		t.Errorf("expected OSVersion=3.19.0, got %q", info.OSVersion)
	}
}

func TestParseCycloneDXWithInfo_MetadataProperties(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	// Properties should be extracted (distro name/version from properties)
	// Since metadata.component already sets OSName, properties are fallbacks
	if info.OSName == "" {
		t.Error("expected OSName to be set from metadata")
	}
}

func TestParseCycloneDXWithInfo_ImageTag(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.SourceName != "alpine:3.19" {
		t.Errorf("expected SourceName=alpine:3.19, got %q", info.SourceName)
	}
}

func TestParseCycloneDXWithInfo_NoMetadata(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.OSName != "" || info.OSVersion != "" || info.SourceName != "" {
		t.Errorf("expected empty SBOMInfo for CycloneDX without metadata, got %+v", info)
	}
}

func TestParseCycloneDX_ComplexLicenses(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-complex-licenses.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 3 {
		t.Fatalf("expected 3 components, got %d", len(comps))
	}

	for _, c := range comps {
		switch c.Name {
		case "multi-license-pkg":
			// Has license IDs: MIT, Apache-2.0 (expression is not extracted as ID)
			if len(c.Licenses) != 2 {
				t.Errorf("expected 2 license IDs for multi-license-pkg, got %d: %v", len(c.Licenses), c.Licenses)
			}
		case "no-id-license-pkg":
			// license.name without license.id should not be extracted
			if len(c.Licenses) != 0 {
				t.Errorf("expected 0 licenses for no-id-license-pkg, got %d: %v", len(c.Licenses), c.Licenses)
			}
		case "no-license-pkg":
			if len(c.Licenses) != 0 {
				t.Errorf("expected 0 licenses for no-license-pkg, got %v", c.Licenses)
			}
		}
	}
}

func TestParseCycloneDX_TopLevelDependencies(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"components": [
			{"type": "library", "bom-ref": "ref-a", "name": "a", "version": "1.0"},
			{"type": "library", "bom-ref": "ref-b", "name": "b", "version": "2.0"}
		],
		"dependencies": [
			{"ref": "ref-a", "dependsOn": ["ref-b"]},
			{"ref": "ref-b", "dependsOn": []}
		]
	}`)
	comps, _, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var a, b *Component
	for i := range comps {
		switch comps[i].Name {
		case "a":
			a = &comps[i]
		case "b":
			b = &comps[i]
		}
	}
	if a == nil || b == nil {
		t.Fatal("expected components a and b")
	}
	if len(a.Dependencies) != 1 {
		t.Fatalf("expected a to have 1 dependency from top-level dependencies, got %d", len(a.Dependencies))
	}
	if a.Dependencies[0] != b.ID {
		t.Errorf("expected a's dependency to be b's ID %q, got %q", b.ID, a.Dependencies[0])
	}
}

func TestParseCycloneDX_MetadataToolsModern(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata": {
			"tools": {"components": [{"type": "application", "name": "syft", "version": "1.40.1"}]}
		},
		"components": [{"type": "library", "bom-ref": "r1", "name": "a", "version": "1.0"}]
	}`)
	_, info, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ToolName != "syft" {
		t.Errorf("expected ToolName syft from metadata.tools.components, got %q", info.ToolName)
	}
	if info.ToolVersion != "1.40.1" {
		t.Errorf("expected ToolVersion 1.40.1, got %q", info.ToolVersion)
	}
}

func TestParseCycloneDX_MetadataToolsLegacy(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
		"metadata": {
			"tools": [{"vendor": "anchore", "name": "syft", "version": "0.90.0"}]
		},
		"components": [{"type": "library", "bom-ref": "r1", "name": "a", "version": "1.0"}]
	}`)
	_, info, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ToolName != "syft" {
		t.Errorf("expected ToolName syft from legacy metadata.tools array, got %q", info.ToolName)
	}
	if info.ToolVersion != "0.90.0" {
		t.Errorf("expected ToolVersion 0.90.0, got %q", info.ToolVersion)
	}
}

func TestParseCycloneDX_EmptyDependsOnIsDeclared(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"components": [
			{"type": "library", "bom-ref": "ref-a", "name": "a", "version": "1.0"},
			{"type": "library", "bom-ref": "ref-b", "name": "b", "version": "2.0"}
		],
		"dependencies": [
			{"ref": "ref-a", "dependsOn": ["ref-b"]},
			{"ref": "ref-b", "dependsOn": []}
		]
	}`)
	comps, _, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range comps {
		if c.Name == "b" && !c.DepsDeclared {
			t.Error("expected b.DepsDeclared=true: empty dependsOn is an explicit leaf declaration")
		}
	}
}

func TestParseCycloneDX_ComponentType(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"components": [
			{"type": "library", "bom-ref": "r1", "name": "a", "version": "1.0"},
			{"type": "file", "bom-ref": "r2", "name": "/etc/motd"}
		]
	}`)
	comps, _, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	types := map[string]string{}
	for _, c := range comps {
		types[c.Name] = c.Type
	}
	if types["a"] != "library" {
		t.Errorf("expected type 'library' for a, got %q", types["a"])
	}
	if types["/etc/motd"] != "file" {
		t.Errorf("expected type 'file' for /etc/motd, got %q", types["/etc/motd"])
	}
}
