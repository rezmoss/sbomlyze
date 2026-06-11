package sbom

import (
	"os"
	"testing"
)

func TestParseSPDX_BasicPackages(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}
	found := false
	for _, c := range comps {
		if c.Name == "axios" {
			found = true
			if c.Version != "1.6.0" {
				t.Errorf("expected axios version 1.6.0, got %s", c.Version)
			}
			if c.SPDXID != "Package-axios" {
				t.Errorf("expected SPDXID=Package-axios, got %s", c.SPDXID)
			}
		}
	}
	if !found {
		t.Error("expected to find axios component")
	}
}

func TestParseSPDX_PURLFromExternalRefs(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "axios" {
			if c.PURL != "pkg:npm/axios@1.6.0" {
				t.Errorf("expected PURL=pkg:npm/axios@1.6.0, got %s", c.PURL)
			}
			return
		}
	}
	t.Error("axios not found")
}

func TestParseSPDX_CPEFromExternalRefs(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-with-cpes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if len(comps[0].CPEs) != 2 {
		t.Errorf("expected 2 CPEs (cpe22Type + cpe23Type), got %d: %v", len(comps[0].CPEs), comps[0].CPEs)
	}
}

func TestParseSPDX_LicenseConcluded(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "axios" {
			if len(c.Licenses) != 1 || c.Licenses[0] != "MIT" {
				t.Errorf("expected licenses=[MIT], got %v", c.Licenses)
			}
			return
		}
	}
	t.Error("axios not found")
}

func TestParseSPDX_Checksums(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "axios" {
			if c.Hashes["SHA256"] != "abc123" {
				t.Errorf("expected SHA256=abc123, got %s", c.Hashes["SHA256"])
			}
			return
		}
	}
	t.Error("axios not found")
}

func TestParseSPDX_RawJSON(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if len(c.RawJSON) == 0 {
			t.Errorf("expected RawJSON populated for %s", c.Name)
		}
	}
}

func TestParseSPDX_IDComputed(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.ID == "" {
			t.Errorf("expected ID computed for %s", c.Name)
		}
	}
}

func TestParseSPDX_EmptyPackages(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-no-packages.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 0 {
		t.Errorf("expected 0 components, got %d", len(comps))
	}
}

func TestParseSPDX_InvalidFile(t *testing.T) {
	_, err := ParseSPDX("nonexistent-file.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseSPDXFromBytes(t *testing.T) {
	data, err := os.ReadFile(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	compsFromBytes, err := ParseSPDXFromBytes(data)
	if err != nil {
		t.Fatalf("ParseSPDXFromBytes error: %v", err)
	}
	compsFromFile, err := ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatalf("ParseSPDX error: %v", err)
	}
	if len(compsFromBytes) != len(compsFromFile) {
		t.Errorf("expected same count: bytes=%d, file=%d", len(compsFromBytes), len(compsFromFile))
	}
}

func TestParseSPDXFromBytes_InvalidJSON(t *testing.T) {
	_, err := ParseSPDXFromBytes([]byte("not valid json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseSPDX_MultipleChecksums(t *testing.T) {
	comps, err := ParseSPDX(testdataPath("spdx-complex.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "openssl" {
			if len(c.Hashes) != 3 {
				t.Errorf("expected 3 checksums for openssl, got %d: %v", len(c.Hashes), c.Hashes)
			}
			return
		}
	}
	t.Error("openssl not found")
}

const spdxRelationshipsDoc = `{
	"spdxVersion": "SPDX-2.3",
	"dataLicense": "CC0-1.0",
	"SPDXID": "SPDXRef-DOCUMENT",
	"name": "test-doc",
	"documentNamespace": "https://example.com/test",
	"creationInfo": {
		"created": "2025-01-01T00:00:00Z",
		"creators": ["Organization: Acme Corp"]
	},
	"packages": [
		{"name": "a", "SPDXID": "SPDXRef-Package-a", "versionInfo": "1.0",
		 "downloadLocation": "NOASSERTION", "supplier": "Organization: Acme Corp"},
		{"name": "b", "SPDXID": "SPDXRef-Package-b", "versionInfo": "2.0",
		 "downloadLocation": "NOASSERTION", "originator": "Person: Jane Doe"},
		{"name": "c", "SPDXID": "SPDXRef-Package-c", "versionInfo": "3.0",
		 "downloadLocation": "NOASSERTION"}
	],
	"relationships": [
		{"spdxElementId": "SPDXRef-Package-a", "relationshipType": "DEPENDS_ON",
		 "relatedSpdxElement": "SPDXRef-Package-b"},
		{"spdxElementId": "SPDXRef-Package-c", "relationshipType": "DEPENDENCY_OF",
		 "relatedSpdxElement": "SPDXRef-Package-b"}
	]
}`

func TestParseSPDX_Supplier(t *testing.T) {
	comps, _, err := parseSPDXData([]byte(spdxRelationshipsDoc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byName := map[string]Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	if got := byName["a"].Supplier; got != "Acme Corp" {
		t.Errorf("expected supplier 'Acme Corp' from PackageSupplier, got %q", got)
	}
	if got := byName["b"].Supplier; got != "Jane Doe" {
		t.Errorf("expected supplier 'Jane Doe' from originator fallback, got %q", got)
	}
	if got := byName["c"].Supplier; got != "" {
		t.Errorf("expected empty supplier for package c, got %q", got)
	}
}

func TestParseSPDX_DependencyRelationships(t *testing.T) {
	comps, _, err := parseSPDXData([]byte(spdxRelationshipsDoc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byName := map[string]Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// DEPENDS_ON: a depends on b
	if len(byName["a"].Dependencies) != 1 || byName["a"].Dependencies[0] != byName["b"].ID {
		t.Errorf("expected a.Dependencies = [b.ID] from DEPENDS_ON, got %v", byName["a"].Dependencies)
	}
	// DEPENDENCY_OF: c is a dependency of b
	if len(byName["b"].Dependencies) != 1 || byName["b"].Dependencies[0] != byName["c"].ID {
		t.Errorf("expected b.Dependencies = [c.ID] from DEPENDENCY_OF, got %v", byName["b"].Dependencies)
	}
}

func TestParseSPDX_CreatorTypes(t *testing.T) {
	doc := `{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-doc",
		"documentNamespace": "https://example.com/test",
		"creationInfo": {
			"created": "2025-01-01T00:00:00Z",
			"creators": ["Tool: syft-1.40.1", "Organization: Anchore, Inc"]
		},
		"packages": [
			{"name": "a", "SPDXID": "SPDXRef-Package-a", "versionInfo": "1.0",
			 "downloadLocation": "NOASSERTION"}
		]
	}`
	_, info, err := parseSPDXData([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SBOMAuthor != "Anchore, Inc" {
		t.Errorf("expected SBOMAuthor 'Anchore, Inc' (Organization creator), got %q", info.SBOMAuthor)
	}
	if info.ToolName != "syft" {
		t.Errorf("expected ToolName 'syft' from Tool creator, got %q", info.ToolName)
	}
	if info.ToolVersion != "1.40.1" {
		t.Errorf("expected ToolVersion '1.40.1' from Tool creator, got %q", info.ToolVersion)
	}
}

func TestParseSPDX_ToolOnlyCreatorIsNotAuthor(t *testing.T) {
	doc := `{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-doc",
		"documentNamespace": "https://example.com/test",
		"creationInfo": {
			"created": "2025-01-01T00:00:00Z",
			"creators": ["Tool: test"]
		},
		"packages": [
			{"name": "a", "SPDXID": "SPDXRef-Package-a", "versionInfo": "1.0",
			 "downloadLocation": "NOASSERTION"}
		]
	}`
	_, info, err := parseSPDXData([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SBOMAuthor != "" {
		t.Errorf("expected empty SBOMAuthor for tool-only creators, got %q", info.SBOMAuthor)
	}
	if info.ToolName != "test" {
		t.Errorf("expected ToolName 'test' from Tool creator, got %q", info.ToolName)
	}
}

func TestParseSPDX_DependsOnNoneAndNoassertion(t *testing.T) {
	doc := `{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-doc",
		"documentNamespace": "https://example.com/test",
		"creationInfo": {
			"created": "2025-01-01T00:00:00Z",
			"creators": ["Organization: Acme Corp"]
		},
		"packages": [
			{"name": "a", "SPDXID": "SPDXRef-Package-a", "versionInfo": "1.0",
			 "downloadLocation": "NOASSERTION"},
			{"name": "b", "SPDXID": "SPDXRef-Package-b", "versionInfo": "2.0",
			 "downloadLocation": "NOASSERTION"}
		],
		"relationships": [
			{"spdxElementId": "SPDXRef-Package-a", "relationshipType": "DEPENDS_ON",
			 "relatedSpdxElement": "NONE"},
			{"spdxElementId": "SPDXRef-Package-b", "relationshipType": "DEPENDS_ON",
			 "relatedSpdxElement": "NOASSERTION"}
		]
	}`
	comps, _, err := parseSPDXData([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byName := map[string]Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// DEPENDS_ON NONE = affirmative "no dependencies" -> declared
	if !byName["a"].DepsDeclared {
		t.Error("expected a.DepsDeclared=true for DEPENDS_ON NONE")
	}
	// DEPENDS_ON NOASSERTION = unknown -> NOT declared (known-unknowns)
	if byName["b"].DepsDeclared {
		t.Error("expected b.DepsDeclared=false for DEPENDS_ON NOASSERTION")
	}
}

func TestParseSPDX_LicenseDeclaredFallback(t *testing.T) {
	mk := func(concluded, declared string) string {
		pkg := `{"name": "a", "SPDXID": "SPDXRef-Package-a", "versionInfo": "1.0",
			 "downloadLocation": "NOASSERTION"`
		if concluded != "" {
			pkg += `, "licenseConcluded": "` + concluded + `"`
		}
		if declared != "" {
			pkg += `, "licenseDeclared": "` + declared + `"`
		}
		pkg += `}`
		return `{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
			"SPDXID": "SPDXRef-DOCUMENT", "name": "t",
			"documentNamespace": "https://example.com/t",
			"creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: test"]},
			"packages": [` + pkg + `]}`
	}
	cases := []struct {
		concluded, declared string
		want                []string
	}{
		{"NOASSERTION", "MIT", []string{"MIT"}},   // declared fallback
		{"Apache-2.0", "MIT", []string{"Apache-2.0"}}, // concluded wins
		{"NOASSERTION", "NOASSERTION", nil},       // neither meaningful
		{"NONE", "", nil},
	}
	for _, tc := range cases {
		comps, _, err := parseSPDXData([]byte(mk(tc.concluded, tc.declared)))
		if err != nil {
			t.Fatalf("concluded=%q declared=%q: %v", tc.concluded, tc.declared, err)
		}
		got := comps[0].Licenses
		if len(got) != len(tc.want) || (len(got) > 0 && got[0] != tc.want[0]) {
			t.Errorf("concluded=%q declared=%q: licenses=%v, want %v", tc.concluded, tc.declared, got, tc.want)
		}
	}
}
