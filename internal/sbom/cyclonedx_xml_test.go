package sbom

import (
	"os"
	"testing"
)

func TestIsCycloneDXXML_Valid(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !IsCycloneDXXML(data) {
		t.Error("expected IsCycloneDXXML to return true for CycloneDX XML")
	}
}

func TestIsCycloneDXXML_Valid1_5(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components/>
</bom>`)
	if !IsCycloneDXXML(data) {
		t.Error("expected IsCycloneDXXML to return true for spec 1.5")
	}
}

func TestIsCycloneDXXML_ValidWithProlog(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components/>
</bom>`)
	if !IsCycloneDXXML(data) {
		t.Error("expected IsCycloneDXXML to return true with XML prolog")
	}
}

func TestIsCycloneDXXML_NegativeJSON(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`)
	if IsCycloneDXXML(data) {
		t.Error("expected IsCycloneDXXML to return false for JSON data")
	}
}

func TestIsCycloneDXXML_NegativeNonCycloneDXXML(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<archive xmlns="http://example.com/other"/>`)
	if IsCycloneDXXML(data) {
		t.Error("expected IsCycloneDXXML to return false for non-CycloneDX XML")
	}
}

func TestIsCycloneDXXML_NegativeRootElement(t *testing.T) {
	// XML but root element is not <bom>
	data := []byte(`<?xml version="1.0"?>
<document xmlns="http://cyclonedx.org/schema/bom/1.4"/>`)
	if IsCycloneDXXML(data) {
		t.Error("expected IsCycloneDXXML to return false when root element is not <bom>")
	}
}

func TestIsCycloneDXXML_NegativeWrongNamespace(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<bom xmlns="http://example.com/not-cyclonedx"/>`)
	if IsCycloneDXXML(data) {
		t.Error("expected IsCycloneDXXML to return false with wrong namespace")
	}
}

func TestIsCycloneDXXML_NegativeEmpty(t *testing.T) {
	if IsCycloneDXXML([]byte{}) {
		t.Error("expected IsCycloneDXXML to return false for empty data")
	}
}

func TestParseCycloneDXXML_BasicComponents(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.xml"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDXXML(data)
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

func TestParseCycloneDXXML_Licenses(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.xml"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDXXML(data)
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

func TestParseCycloneDXXML_Hashes(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.xml"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDXXML(data)
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

func TestParseCycloneDXXML_IDComputed(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.xml"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDXXML(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.ID == "" {
			t.Errorf("expected ID to be computed for component %s", c.Name)
		}
		if c.Name == "lodash" {
			if c.ID != "pkg:npm/lodash" {
				t.Errorf("expected ID=pkg:npm/lodash, got %s", c.ID)
			}
		}
	}
}

func TestParseCycloneDXXML_Supplier(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.xml"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDXXML(data)
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

func TestParseCycloneDXXML_Namespace(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.xml"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDXXML(data)
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

func TestParseCycloneDXXMLWithInfo_MetadataOS(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.xml"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseCycloneDXXMLWithInfo(data)
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

func TestParseCycloneDXXMLWithInfo_ImageTag(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-with-metadata.xml"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseCycloneDXXMLWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.SourceName != "alpine:3.19" {
		t.Errorf("expected SourceName=alpine:3.19, got %q", info.SourceName)
	}
}

func TestParseCycloneDXXML_InvalidXML(t *testing.T) {
	_, err := ParseCycloneDXXML([]byte("not valid xml"))
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
}

func TestParseCycloneDXXML_Dependencies(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="ref-a">
      <name>a</name>
      <version>1.0</version>
    </component>
    <component type="library" bom-ref="ref-b">
      <name>b</name>
      <version>2.0</version>
    </component>
  </components>
  <dependencies>
    <dependency ref="ref-a">
      <dependency ref="ref-b"/>
    </dependency>
    <dependency ref="ref-b"/>
  </dependencies>
</bom>`)
	comps, _, err := ParseCycloneDXXMLWithInfo(data)
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
		t.Fatalf("expected a to have 1 dependency, got %d", len(a.Dependencies))
	}
	if a.Dependencies[0] != b.ID {
		t.Errorf("expected a's dependency to be b's ID %q, got %q", b.ID, a.Dependencies[0])
	}
	if !b.DepsDeclared {
		t.Error("expected b.DepsDeclared=true: empty dependency is an explicit leaf declaration")
	}
}

func TestParseCycloneDXXML_NoComponents(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1"/>`)
	comps, _, err := ParseCycloneDXXMLWithInfo(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 0 {
		t.Errorf("expected 0 components, got %d", len(comps))
	}
}

func TestParseCycloneDXXML_LicenseExpression(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="r1">
      <name>expr-pkg</name>
      <version>1.0</version>
      <licenses>
        <expression>MIT AND BSD-2-Clause</expression>
      </licenses>
    </component>
  </components>
</bom>`)
	comps, err := ParseCycloneDXXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if len(comps[0].Licenses) != 1 || comps[0].Licenses[0] != "MIT AND BSD-2-Clause" {
		t.Errorf("expected expression license, got %v", comps[0].Licenses)
	}
}

func TestParseCycloneDXXML_RawJSONNil(t *testing.T) {
	// XML components should not have RawJSON populated (it's JSON-specific)
	data, err := os.ReadFile(testdataPath("cyclonedx-before.xml"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseCycloneDXXML(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.RawJSON != nil {
			t.Errorf("expected RawJSON to be nil for XML component %s", c.Name)
		}
	}
}
