package convert

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/common"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func sampleSPDXComponents() []sbom.Component {
	return []sbom.Component{
		{
			Name:     "axios",
			Version:  "1.6.0",
			PURL:     "pkg:npm/axios@1.6.0",
			SPDXID:   "SPDXRef-Package-axios",
			Supplier: "Axios Corp",
			Licenses: []string{"MIT", "Apache-2.0"},
			CPEs: []string{
				"cpe:2.3:a:axios:axios:1.6.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:axios_project:axios:1.6.0:*:*:*:*:*:*:*",
			},
			Hashes: map[string]string{
				"SHA256": "abcdef1234567890",
				"MD5":    "1234567890abcdef",
			},
			Dependencies: []string{"dep-follow"},
			ID:           "comp-axios",
		},
		{
			Name:    "follow-redirects",
			Version: "1.15.0",
			PURL:    "pkg:npm/follow-redirects@1.15.0",
			ID:      "dep-follow",
		},
	}
}

func sampleSPDXInfo() sbom.SBOMInfo {
	return sbom.SBOMInfo{
		SourceName: "test-project",
		SourceType: "directory",
	}
}

func TestWriteSPDX_ValidStructure(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if v, ok := raw["spdxVersion"].(string); !ok || !strings.HasPrefix(v, "SPDX-") {
		t.Errorf("spdxVersion = %v, want SPDX-* prefix", raw["spdxVersion"])
	}

	if v, ok := raw["dataLicense"].(string); !ok || v != "CC0-1.0" {
		t.Errorf("dataLicense = %v, want CC0-1.0", raw["dataLicense"])
	}

	if v, ok := raw["SPDXID"].(string); !ok || v != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %v, want SPDXRef-DOCUMENT", raw["SPDXID"])
	}
}

func TestWriteSPDX_RequiredDocFields(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	requiredFields := []string{"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("Required field %q is missing", field)
		}
	}
}

func TestWriteSPDX_RequiredPackageFields(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	if len(doc.Packages) == 0 {
		t.Fatal("No packages in output")
	}

	for i, pkg := range doc.Packages {
		if pkg.PackageName == "" {
			t.Errorf("package[%d]: PackageName is empty", i)
		}
		if pkg.PackageSPDXIdentifier == "" {
			t.Errorf("package[%d]: PackageSPDXIdentifier is empty", i)
		}
		if pkg.PackageDownloadLocation != "NOASSERTION" {
			t.Errorf("package[%d]: PackageDownloadLocation = %q, want \"NOASSERTION\"", i, pkg.PackageDownloadLocation)
		}
		if pkg.PackageCopyrightText != "NOASSERTION" {
			t.Errorf("package[%d]: PackageCopyrightText = %q, want \"NOASSERTION\"", i, pkg.PackageCopyrightText)
		}
		if pkg.FilesAnalyzed {
			t.Errorf("package[%d]: FilesAnalyzed = true, want false", i)
		}
	}
}

func TestWriteSPDX_RequiredDocFieldValues(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDXVersion = %q, want \"SPDX-2.3\"", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("DataLicense = %q, want \"CC0-1.0\"", doc.DataLicense)
	}
	if doc.SPDXIdentifier != "DOCUMENT" {
		t.Errorf("SPDXIdentifier = %q, want \"DOCUMENT\"", doc.SPDXIdentifier)
	}
	if doc.DocumentName == "" {
		t.Error("DocumentName is empty")
	}
	if doc.DocumentNamespace == "" {
		t.Error("DocumentNamespace is empty")
	}
	if !strings.HasPrefix(doc.DocumentNamespace, "https://") {
		t.Errorf("DocumentNamespace = %q, want https:// prefix", doc.DocumentNamespace)
	}
	if doc.CreationInfo == nil {
		t.Fatal("CreationInfo is nil")
	}
	if doc.CreationInfo.Created == "" {
		t.Error("CreationInfo.Created is empty")
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("CreationInfo.Creators is empty")
	}
}

func TestWriteSPDX_ReParseRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse SPDX output: %v", err)
	}

	if len(doc.Packages) != 2 {
		t.Errorf("Re-parsed packages count = %d, want 2", len(doc.Packages))
	}

	pkg := doc.Packages[0]
	if pkg.PackageName != "axios" {
		t.Errorf("Package name = %q, want %q", pkg.PackageName, "axios")
	}
	if pkg.PackageVersion != "1.6.0" {
		t.Errorf("Package version = %q, want %q", pkg.PackageVersion, "1.6.0")
	}
}

func TestWriteSPDX_PURLExternalRef(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	pkg := doc.Packages[0]
	foundPURL := false
	for _, ref := range pkg.PackageExternalReferences {
		if ref.RefType == common.TypePackageManagerPURL {
			if ref.Locator != "pkg:npm/axios@1.6.0" {
				t.Errorf("PURL locator = %q, want %q", ref.Locator, "pkg:npm/axios@1.6.0")
			}
			if ref.Category != common.CategoryPackageManager {
				t.Errorf("PURL category = %q, want %q", ref.Category, common.CategoryPackageManager)
			}
			foundPURL = true
		}
	}
	if !foundPURL {
		t.Error("PURL external reference not found")
	}
}

func TestWriteSPDX_CPEExternalRefs(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	pkg := doc.Packages[0]
	cpeCount := 0
	for _, ref := range pkg.PackageExternalReferences {
		if ref.RefType == common.TypeSecurityCPE23Type {
			cpeCount++
			if ref.Category != common.CategorySecurity {
				t.Errorf("CPE category = %q, want %q", ref.Category, common.CategorySecurity)
			}
			if !strings.HasPrefix(ref.Locator, "cpe:2.3:") {
				t.Errorf("CPE locator doesn't start with cpe:2.3: got %q", ref.Locator)
			}
		}
	}
	if cpeCount != 2 {
		t.Errorf("CPE external ref count = %d, want 2", cpeCount)
	}
}

func TestWriteSPDX_LicenseConcluded(t *testing.T) {
	tests := []struct {
		name     string
		licenses []string
		want     string
	}{
		{
			name:     "multiple licenses joined with AND",
			licenses: []string{"MIT", "Apache-2.0"},
			want:     "MIT AND Apache-2.0",
		},
		{
			name:     "single license",
			licenses: []string{"MIT"},
			want:     "MIT",
		},
		{
			name:     "no licenses",
			licenses: nil,
			want:     "NOASSERTION",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			comps := []sbom.Component{
				{Name: "test", Version: "1.0", Licenses: tt.licenses},
			}
			err := WriteSPDX(&buf, comps, sbom.SBOMInfo{})
			if err != nil {
				t.Fatalf("WriteSPDX failed: %v", err)
			}

			doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("Failed to re-parse: %v", err)
			}

			pkg := doc.Packages[0]
			if pkg.PackageLicenseConcluded != tt.want {
				t.Errorf("PackageLicenseConcluded = %q, want %q", pkg.PackageLicenseConcluded, tt.want)
			}
		})
	}
}

func TestWriteSPDX_Checksums(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:    "test",
			Version: "1.0",
			Hashes: map[string]string{
				"SHA-256": "abcdef1234567890",
			},
		},
	}
	err := WriteSPDX(&buf, comps, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	pkg := doc.Packages[0]
	if len(pkg.PackageChecksums) == 0 {
		t.Fatal("No checksums on package")
	}

	cs := pkg.PackageChecksums[0]
	if cs.Algorithm != common.SHA256 {
		t.Errorf("Checksum algorithm = %q, want %q", cs.Algorithm, common.SHA256)
	}
	if cs.Value != "abcdef1234567890" {
		t.Errorf("Checksum value = %q, want %q", cs.Value, "abcdef1234567890")
	}
}

func TestWriteSPDX_Supplier(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	pkg := doc.Packages[0]
	if pkg.PackageSupplier == nil {
		t.Fatal("PackageSupplier is nil")
	}
	if pkg.PackageSupplier.Supplier != "Axios Corp" {
		t.Errorf("Supplier = %q, want %q", pkg.PackageSupplier.Supplier, "Axios Corp")
	}
	if pkg.PackageSupplier.SupplierType != "Organization" {
		t.Errorf("SupplierType = %q, want %q", pkg.PackageSupplier.SupplierType, "Organization")
	}
}

func TestWriteSPDX_SPDXIDFormat(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{Name: "test-pkg", Version: "1.0.0"},
		{Name: "another/pkg", Version: "2.0"},
		{Name: "pkg with spaces", Version: "3.0"},
		{SPDXID: "SPDXRef-existing-id", Name: "existing"},
	}
	err := WriteSPDX(&buf, comps, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	spdxIDPattern := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	for _, pkg := range doc.Packages {
		id := string(pkg.PackageSPDXIdentifier)
		if !spdxIDPattern.MatchString(id) {
			t.Errorf("SPDXID %q does not match pattern [a-zA-Z0-9.-]+", id)
		}
	}
}

func TestWriteSPDX_DescribesRelationships(t *testing.T) {
	var buf bytes.Buffer
	comps := sampleSPDXComponents()
	err := WriteSPDX(&buf, comps, sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	describesCount := 0
	for _, rel := range doc.Relationships {
		if rel.Relationship == common.TypeRelationshipDescribe {
			if string(rel.RefA.ElementRefID) != "DOCUMENT" {
				t.Errorf("DESCRIBES RefA = %q, want DOCUMENT", rel.RefA.ElementRefID)
			}
			describesCount++
		}
	}

	if describesCount != len(comps) {
		t.Errorf("DESCRIBES relationship count = %d, want %d", describesCount, len(comps))
	}
}

func TestWriteSPDX_DependsOnRelationships(t *testing.T) {
	var buf bytes.Buffer
	comps := sampleSPDXComponents()
	err := WriteSPDX(&buf, comps, sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	dependsOnCount := 0
	for _, rel := range doc.Relationships {
		if rel.Relationship == common.TypeRelationshipDependsOn {
			dependsOnCount++
		}
	}

	if dependsOnCount < 1 {
		t.Errorf("DEPENDS_ON relationship count = %d, want at least 1", dependsOnCount)
	}
}

func TestWriteSPDX_DocumentNamespace(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	ns, ok := raw["documentNamespace"].(string)
	if !ok || ns == "" {
		t.Fatal("documentNamespace is missing or empty")
	}
	if !strings.HasPrefix(ns, "https://") {
		t.Errorf("documentNamespace = %q, should be a valid URI starting with https://", ns)
	}
}

func TestWriteSPDX_CreationInfo(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, sampleSPDXComponents(), sampleSPDXInfo())
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	if doc.CreationInfo == nil {
		t.Fatal("CreationInfo is nil")
	}
	if doc.CreationInfo.Created == "" {
		t.Error("Created timestamp is empty")
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Fatal("No creators in CreationInfo")
	}

	foundTool := false
	for _, creator := range doc.CreationInfo.Creators {
		if creator.CreatorType == "Tool" {
			foundTool = true
			if !strings.Contains(creator.Creator, "sbomlyze") {
				t.Errorf("Tool creator = %q, want to contain 'sbomlyze'", creator.Creator)
			}
		}
	}
	if !foundTool {
		t.Error("No Tool creator found in CreationInfo")
	}
}

func TestWriteSPDX_EmptyInput(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSPDX(&buf, nil, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteSPDX with nil components failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse empty SPDX doc: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDXVersion = %q, want SPDX-2.3", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("DataLicense = %q, want CC0-1.0", doc.DataLicense)
	}

	if len(doc.Packages) > 0 {
		t.Errorf("Expected zero packages, got %d", len(doc.Packages))
	}
}

func TestWriteSPDX_DocumentName(t *testing.T) {
	tests := []struct {
		name       string
		info       sbom.SBOMInfo
		wantName   string
	}{
		{
			name:     "with source name",
			info:     sbom.SBOMInfo{SourceName: "my-project"},
			wantName: "my-project",
		},
		{
			name:     "without source name",
			info:     sbom.SBOMInfo{},
			wantName: "sbomlyze-converted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteSPDX(&buf, nil, tt.info)
			if err != nil {
				t.Fatalf("WriteSPDX failed: %v", err)
			}

			doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("Failed to re-parse: %v", err)
			}

			if doc.DocumentName != tt.wantName {
				t.Errorf("DocumentName = %q, want %q", doc.DocumentName, tt.wantName)
			}
		})
	}
}

func TestWriteSPDX_HashAlgorithmNormalization(t *testing.T) {
	tests := []struct {
		input string
		want  common.ChecksumAlgorithm
	}{
		{"SHA-256", common.SHA256},
		{"SHA256", common.SHA256},
		{"SHA-512", common.SHA512},
		{"SHA512", common.SHA512},
		{"SHA-1", common.SHA1},
		{"SHA1", common.SHA1},
		{"MD5", common.MD5},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var buf bytes.Buffer
			comps := []sbom.Component{
				{Name: "test", Version: "1.0", Hashes: map[string]string{tt.input: "deadbeef"}},
			}
			if err := WriteSPDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
				t.Fatalf("WriteSPDX failed: %v", err)
			}

			doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("Failed to re-parse: %v", err)
			}

			pkg := doc.Packages[0]
			if len(pkg.PackageChecksums) != 1 {
				t.Fatalf("checksum count = %d, want 1", len(pkg.PackageChecksums))
			}
			cs := pkg.PackageChecksums[0]
			if cs.Algorithm != tt.want {
				t.Errorf("checksum algorithm = %q, want %q", cs.Algorithm, tt.want)
			}
			if cs.Value != "deadbeef" {
				t.Errorf("checksum value = %q, want %q", cs.Value, "deadbeef")
			}
		})
	}
}

func TestWriteSPDX_MultipleHashes(t *testing.T) {
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
	if err := WriteSPDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	pkg := doc.Packages[0]
	if len(pkg.PackageChecksums) != 3 {
		t.Errorf("checksum count = %d, want 3", len(pkg.PackageChecksums))
	}

	csMap := make(map[common.ChecksumAlgorithm]string)
	for _, cs := range pkg.PackageChecksums {
		csMap[cs.Algorithm] = cs.Value
	}
	if csMap[common.SHA256] != "abc123" {
		t.Errorf("SHA256 value = %q, want abc123", csMap[common.SHA256])
	}
	if csMap[common.MD5] != "def456" {
		t.Errorf("MD5 value = %q, want def456", csMap[common.MD5])
	}
	if csMap[common.SHA512] != "789xyz" {
		t.Errorf("SHA512 value = %q, want 789xyz", csMap[common.SHA512])
	}
}

func TestWriteSPDX_MultipleLicenses(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:     "test",
			Version:  "1.0",
			Licenses: []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
	}
	if err := WriteSPDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	pkg := doc.Packages[0]
	want := "MIT AND Apache-2.0 AND BSD-3-Clause"
	if pkg.PackageLicenseConcluded != want {
		t.Errorf("PackageLicenseConcluded = %q, want %q", pkg.PackageLicenseConcluded, want)
	}
}

func TestWriteSPDX_MultipleCPEsPreserved(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:    "test",
			Version: "1.0",
			CPEs: []string{
				"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:other:product:1.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:third:product:1.0:*:*:*:*:*:*:*",
			},
		},
	}
	if err := WriteSPDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	pkg := doc.Packages[0]
	cpeCount := 0
	for _, ref := range pkg.PackageExternalReferences {
		if ref.RefType == common.TypeSecurityCPE23Type {
			cpeCount++
		}
	}
	// SPDX preserves all CPEs
	if cpeCount != 3 {
		t.Errorf("CPE external ref count = %d, want 3 (all CPEs preserved)", cpeCount)
	}
}

func TestWriteSPDX_SPDXIDReuse(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{Name: "test", Version: "1.0", SPDXID: "SPDXRef-Package-test"},
		{Name: "other", Version: "2.0", SPDXID: "Package-other"},
		{Name: "noid", Version: "3.0"},
	}
	if err := WriteSPDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	if string(doc.Packages[0].PackageSPDXIdentifier) != "Package-test" {
		t.Errorf("pkg[0] SPDXID = %q, want \"Package-test\" (stripped SPDXRef-)", doc.Packages[0].PackageSPDXIdentifier)
	}
	if string(doc.Packages[1].PackageSPDXIdentifier) != "Package-other" {
		t.Errorf("pkg[1] SPDXID = %q, want \"Package-other\"", doc.Packages[1].PackageSPDXIdentifier)
	}
	if string(doc.Packages[2].PackageSPDXIdentifier) == "" {
		t.Error("pkg[2] SPDXID should not be empty")
	}
}

func TestWriteSPDX_NoSupplierWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{Name: "test", Version: "1.0"},
	}
	err := WriteSPDX(&buf, comps, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	doc, err := spdxjson.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed to re-parse: %v", err)
	}

	pkg := doc.Packages[0]
	if pkg.PackageSupplier != nil && pkg.PackageSupplier.Supplier != "" {
		t.Errorf("PackageSupplier should be nil or empty when no supplier, got %v", pkg.PackageSupplier)
	}
}
