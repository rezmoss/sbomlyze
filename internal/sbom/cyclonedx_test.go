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
