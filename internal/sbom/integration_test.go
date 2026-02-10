//go:build integration

package sbom

import (
	"os"
	"testing"
)

func TestParseRealSyftAlpine(t *testing.T) {
	path := testdataPath("real-syft-alpine.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("real-syft-alpine.json not generated; run syft alpine:3.19 -o syft-json")
	}

	comps, info, err := ParseSyftWithInfo(readTestData(t, path))
	if err != nil {
		t.Fatalf("failed to parse real Syft Alpine SBOM: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("expected >0 components from real Syft Alpine SBOM")
	}

	// Verify all components have names
	for _, c := range comps {
		if c.Name == "" {
			t.Error("found component with empty name")
		}
	}

	// Verify PURLs are populated
	purlCount := 0
	for _, c := range comps {
		if c.PURL != "" {
			purlCount++
		}
	}
	if purlCount == 0 {
		t.Error("expected at least some components with PURLs")
	}

	// Verify source info
	if info.SourceType != "image" {
		t.Errorf("expected source type 'image', got %q", info.SourceType)
	}
}

func TestParseRealCycloneDXAlpine(t *testing.T) {
	path := testdataPath("real-cyclonedx-alpine.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("real-cyclonedx-alpine.json not generated")
	}

	comps, info, err := ParseCycloneDXWithInfo(readTestData(t, path))
	if err != nil {
		t.Fatalf("failed to parse real CycloneDX Alpine SBOM: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("expected >0 components from real CycloneDX Alpine SBOM")
	}

	// Verify names are populated (versions may be empty for file-level components)
	for _, c := range comps {
		if c.Name == "" {
			t.Error("found component with empty name")
		}
	}

	// Count components with versions (packages should have them, files may not)
	withVersion := 0
	for _, c := range comps {
		if c.Version != "" {
			withVersion++
		}
	}
	if withVersion == 0 {
		t.Error("expected at least some components with versions")
	}
	t.Logf("%d/%d components have versions", withVersion, len(comps))

	// CycloneDX from Syft should have OS info
	if info.OSName == "" {
		t.Log("warning: no OS name extracted from CycloneDX metadata")
	}
}

func TestParseRealSPDXAlpine(t *testing.T) {
	path := testdataPath("real-spdx-alpine.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("real-spdx-alpine.json not generated")
	}

	comps, err := ParseSPDX(path)
	if err != nil {
		t.Fatalf("failed to parse real SPDX Alpine SBOM: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("expected >0 components from real SPDX Alpine SBOM")
	}

	for _, c := range comps {
		if c.Name == "" {
			t.Error("found component with empty name")
		}
	}

	// Verify PURLs from external refs
	purlCount := 0
	for _, c := range comps {
		if c.PURL != "" {
			purlCount++
		}
	}
	if purlCount == 0 {
		t.Error("expected at least some components with PURLs from external refs")
	}
}

func TestCrossFormatConsistency(t *testing.T) {
	syftPath := testdataPath("real-syft-alpine.json")
	cdxPath := testdataPath("real-cyclonedx-alpine.json")
	spdxPath := testdataPath("real-spdx-alpine.json")

	for _, p := range []string{syftPath, cdxPath, spdxPath} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Skipf("%s not generated", p)
		}
	}

	syftComps, _, err := ParseSyftWithInfo(readTestData(t, syftPath))
	if err != nil {
		t.Fatalf("Syft parse error: %v", err)
	}

	cdxComps, _, err := ParseCycloneDXWithInfo(readTestData(t, cdxPath))
	if err != nil {
		t.Fatalf("CycloneDX parse error: %v", err)
	}

	spdxComps, err := ParseSPDX(spdxPath)
	if err != nil {
		t.Fatalf("SPDX parse error: %v", err)
	}

	t.Logf("Component counts - Syft: %d, CycloneDX: %d, SPDX: %d",
		len(syftComps), len(cdxComps), len(spdxComps))

	// Build PURL sets for each format
	syftPURLs := make(map[string]bool)
	for _, c := range syftComps {
		if c.PURL != "" {
			syftPURLs[c.PURL] = true
		}
	}

	cdxPURLs := make(map[string]bool)
	for _, c := range cdxComps {
		if c.PURL != "" {
			cdxPURLs[c.PURL] = true
		}
	}

	spdxPURLs := make(map[string]bool)
	for _, c := range spdxComps {
		if c.PURL != "" {
			spdxPURLs[c.PURL] = true
		}
	}

	// Check Syft vs CycloneDX overlap (should be very high since both from same image)
	overlap := 0
	for purl := range syftPURLs {
		if cdxPURLs[purl] {
			overlap++
		}
	}
	if len(syftPURLs) > 0 {
		overlapPct := float64(overlap) / float64(len(syftPURLs)) * 100
		t.Logf("Syft vs CycloneDX PURL overlap: %d/%d (%.1f%%)", overlap, len(syftPURLs), overlapPct)
		if overlapPct < 50 {
			t.Errorf("expected >50%% PURL overlap between Syft and CycloneDX, got %.1f%%", overlapPct)
		}
	}
}

func TestRealSBOMNormalization(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{"Syft Alpine", "real-syft-alpine.json"},
		{"CycloneDX Alpine", "real-cyclonedx-alpine.json"},
		{"Syft Python", "real-syft-python.json"},
		{"CycloneDX Node", "real-cyclonedx-node.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := testdataPath(tt.file)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Skipf("%s not generated", tt.file)
			}

			comps, err := ParseFile(path)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			// Normalize should not panic
			normalized := NormalizeComponents(comps)
			if len(normalized) != len(comps) {
				t.Errorf("normalization changed component count: %d -> %d", len(comps), len(normalized))
			}

			// All should have IDs after normalization
			for _, c := range normalized {
				if c.ID == "" {
					t.Errorf("component %s has empty ID after normalization", c.Name)
				}
			}
		})
	}
}

func TestRealSBOMStats(t *testing.T) {
	path := testdataPath("real-syft-alpine.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("real-syft-alpine.json not generated")
	}

	comps, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}

	comps = NormalizeComponents(comps)

	// Verify basic component properties
	hasLicense := false
	hasPURL := false
	for _, c := range comps {
		if len(c.Licenses) > 0 {
			hasLicense = true
		}
		if c.PURL != "" {
			hasPURL = true
		}
	}

	if !hasPURL {
		t.Error("expected at least one component with PURL in real SBOM")
	}
	if !hasLicense {
		t.Error("expected at least one component with license in real SBOM")
	}
}

func TestRealSBOMDiff(t *testing.T) {
	alpinePath := testdataPath("real-syft-alpine.json")
	pythonPath := testdataPath("real-syft-python.json")

	for _, p := range []string{alpinePath, pythonPath} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Skipf("%s not generated", p)
		}
	}

	alpine, err := ParseFile(alpinePath)
	if err != nil {
		t.Fatal(err)
	}

	python, err := ParseFile(pythonPath)
	if err != nil {
		t.Fatal(err)
	}

	alpine = NormalizeComponents(alpine)
	python = NormalizeComponents(python)

	// Different images should have different components
	alpineIDs := make(map[string]bool)
	for _, c := range alpine {
		alpineIDs[c.ID] = true
	}

	newInPython := 0
	for _, c := range python {
		if !alpineIDs[c.ID] {
			newInPython++
		}
	}

	if newInPython == 0 {
		t.Error("expected some components in python image not in alpine")
	}
	t.Logf("Alpine: %d components, Python: %d components, unique to Python: %d",
		len(alpine), len(python), newInPython)
}

func TestCrossFormatDiffAccuracy(t *testing.T) {
	syftPath := testdataPath("real-syft-alpine.json")
	cdxPath := testdataPath("real-cyclonedx-alpine.json")

	for _, p := range []string{syftPath, cdxPath} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Skipf("%s not generated", p)
		}
	}

	syftComps, _, err := ParseSyftWithInfo(readTestData(t, syftPath))
	if err != nil {
		t.Fatalf("Syft parse error: %v", err)
	}

	cdxComps, _, err := ParseCycloneDXWithInfo(readTestData(t, cdxPath))
	if err != nil {
		t.Fatalf("CycloneDX parse error: %v", err)
	}

	syftComps = NormalizeComponents(syftComps)
	cdxComps = NormalizeComponents(cdxComps)

	// Build PURL→Component maps
	syftByPURL := make(map[string]Component)
	for _, c := range syftComps {
		if c.PURL != "" {
			syftByPURL[c.PURL] = c
		}
	}

	cdxByPURL := make(map[string]Component)
	for _, c := range cdxComps {
		if c.PURL != "" {
			cdxByPURL[c.PURL] = c
		}
	}

	// For each Syft component with PURL, verify matching CycloneDX component
	matched := 0
	mismatched := 0
	for purl, syftComp := range syftByPURL {
		if cdxComp, ok := cdxByPURL[purl]; ok {
			matched++
			if syftComp.Name != cdxComp.Name {
				t.Logf("Name mismatch for PURL %s: Syft=%q vs CDX=%q", purl, syftComp.Name, cdxComp.Name)
				mismatched++
			}
			if syftComp.Version != cdxComp.Version {
				t.Logf("Version mismatch for PURL %s: Syft=%q vs CDX=%q", purl, syftComp.Version, cdxComp.Version)
				mismatched++
			}
		}
	}

	if len(syftByPURL) > 0 {
		overlapPct := float64(matched) / float64(len(syftByPURL)) * 100
		t.Logf("Cross-format accuracy: %d/%d Syft PURLs matched in CDX (%.1f%%)", matched, len(syftByPURL), overlapPct)
		if overlapPct < 80 {
			t.Errorf("expected >80%% PURL overlap between Syft and CycloneDX, got %.1f%%", overlapPct)
		}
	}

	if mismatched > 0 {
		t.Logf("Warning: %d name/version mismatches found for matched PURLs", mismatched)
	}
}

func TestCrossFormatIdentityConsistency(t *testing.T) {
	purl := "pkg:apk/alpine/busybox@1.36.1"

	// Simulate CycloneDX origin: has BOMRef + PURL
	cdxComp := Component{
		Name:    "busybox",
		Version: "1.36.1",
		PURL:    purl,
		BOMRef:  "component-busybox-1.36.1",
	}

	// Simulate SPDX origin: has SPDXID + PURL
	spdxComp := Component{
		Name:    "busybox",
		Version: "1.36.1",
		PURL:    purl,
		SPDXID:  "SPDXRef-Package-busybox",
	}

	// Simulate Syft origin: has PURL + CPE
	syftComp := Component{
		Name:    "busybox",
		Version: "1.36.1",
		PURL:    purl,
		CPEs:    []string{"cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*"},
	}

	// All three must produce the same ComputeID (PURL takes precedence)
	cdxID := cdxComp.ComputeID()
	spdxID := spdxComp.ComputeID()
	syftID := syftComp.ComputeID()

	if cdxID != spdxID {
		t.Errorf("CycloneDX ID (%s) != SPDX ID (%s) for same component with PURL", cdxID, spdxID)
	}
	if cdxID != syftID {
		t.Errorf("CycloneDX ID (%s) != Syft ID (%s) for same component with PURL", cdxID, syftID)
	}
	t.Logf("All three formats produce ID: %s", cdxID)
}

func TestCrossFormatIdentityFallback(t *testing.T) {
	// Components WITHOUT PURL: BOMRef vs SPDXID produce different IDs
	cdxComp := Component{
		Name:   "busybox",
		BOMRef: "component-busybox",
	}

	spdxComp := Component{
		Name:   "busybox",
		SPDXID: "SPDXRef-Package-busybox",
	}

	cdxID := cdxComp.ComputeID()
	spdxID := spdxComp.ComputeID()

	// Document known limitation: without PURL, cross-format matching falls back
	// to format-specific identifiers which won't match
	if cdxID == spdxID {
		t.Log("BOMRef and SPDXID produced same ID — unexpected but not wrong")
	} else {
		t.Logf("Known limitation: without PURL, CycloneDX ID (%s) != SPDX ID (%s)", cdxID, spdxID)
		t.Logf("Cross-format matching requires PURL for reliable component identity")
	}

	// Both should still produce valid, non-empty IDs
	if cdxID == "" {
		t.Error("CycloneDX component should have non-empty ID even without PURL")
	}
	if spdxID == "" {
		t.Error("SPDX component should have non-empty ID even without PURL")
	}
}

// readTestData reads raw bytes from a test file
func readTestData(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}
