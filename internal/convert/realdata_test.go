package convert

import (
	"bytes"
	"os"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func skipIfMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("testdata not available: " + path)
	}
}

func TestRealData_CycloneDXAlpine_ToSPDX(t *testing.T) {
	path := testdataPath("real-cyclonedx-alpine.json")
	skipIfMissing(t, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	comps, info, err := sbom.ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse CycloneDX: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed")
	}

	var buf bytes.Buffer
	if err := WriteSPDX(&buf, comps, info); err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	reparsed, err := sbom.ParseSPDXFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse SPDX output: %v", err)
	}

	if len(reparsed) != len(comps) {
		t.Errorf("Component count mismatch: original=%d, converted=%d", len(comps), len(reparsed))
	}

	for i, pkg := range reparsed {
		if pkg.Name == "" {
			t.Errorf("Package %d has empty name", i)
		}
	}
}

func TestRealData_CycloneDXAlpine_ToSyft(t *testing.T) {
	path := testdataPath("real-cyclonedx-alpine.json")
	skipIfMissing(t, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	comps, info, err := sbom.ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse CycloneDX: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed")
	}

	var buf bytes.Buffer
	if err := WriteSyft(&buf, comps, info); err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	reparsed, err := sbom.ParseSyft(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse Syft output: %v", err)
	}

	if len(reparsed) != len(comps) {
		t.Errorf("Component count mismatch: original=%d, converted=%d", len(comps), len(reparsed))
	}
}

func TestRealData_SPDXAlpine_ToCycloneDX(t *testing.T) {
	path := testdataPath("real-spdx-alpine.json")
	skipIfMissing(t, path)

	comps, err := sbom.ParseSPDX(path)
	if err != nil {
		t.Fatalf("Failed to parse SPDX: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed")
	}

	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	reparsed, _, err := sbom.ParseCycloneDXWithInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse CycloneDX output: %v", err)
	}

	if len(reparsed) != len(comps) {
		t.Errorf("Component count mismatch: original=%d, converted=%d", len(comps), len(reparsed))
	}

	for i, c := range reparsed {
		if c.Name == "" {
			t.Errorf("Component %d has empty name", i)
		}
	}
}

func TestRealData_SPDXAlpine_ToSyft(t *testing.T) {
	path := testdataPath("real-spdx-alpine.json")
	skipIfMissing(t, path)

	comps, err := sbom.ParseSPDX(path)
	if err != nil {
		t.Fatalf("Failed to parse SPDX: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed")
	}

	var buf bytes.Buffer
	if err := WriteSyft(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	reparsed, err := sbom.ParseSyft(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse Syft output: %v", err)
	}

	if len(reparsed) != len(comps) {
		t.Errorf("Component count mismatch: original=%d, converted=%d", len(comps), len(reparsed))
	}
}

func TestRealData_SyftAlpine_ToCycloneDX(t *testing.T) {
	path := testdataPath("real-syft-alpine.json")
	skipIfMissing(t, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	comps, info, err := sbom.ParseSyftWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse Syft: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed")
	}

	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, comps, info); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	reparsed, _, err := sbom.ParseCycloneDXWithInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse CycloneDX output: %v", err)
	}

	if len(reparsed) != len(comps) {
		t.Errorf("Component count mismatch: original=%d, converted=%d", len(comps), len(reparsed))
	}

	origPURLs := make(map[string]bool)
	for _, c := range comps {
		if c.PURL != "" {
			origPURLs[c.PURL] = true
		}
	}
	reparsedPURLs := make(map[string]bool)
	for _, c := range reparsed {
		if c.PURL != "" {
			reparsedPURLs[c.PURL] = true
		}
	}
	for purl := range origPURLs {
		if !reparsedPURLs[purl] {
			t.Errorf("PURL %q lost during conversion", purl)
		}
	}
}

func TestRealData_SyftAlpine_ToSPDX(t *testing.T) {
	path := testdataPath("real-syft-alpine.json")
	skipIfMissing(t, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	comps, info, err := sbom.ParseSyftWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse Syft: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed")
	}

	var buf bytes.Buffer
	if err := WriteSPDX(&buf, comps, info); err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	reparsed, err := sbom.ParseSPDXFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse SPDX output: %v", err)
	}

	if len(reparsed) != len(comps) {
		t.Errorf("Component count mismatch: original=%d, converted=%d", len(comps), len(reparsed))
	}
}

func TestRealData_SyftPython_ToCycloneDX(t *testing.T) {
	path := testdataPath("real-syft-python.json")
	skipIfMissing(t, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	comps, info, err := sbom.ParseSyftWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse Syft: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed")
	}

	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, comps, info); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	reparsed, _, err := sbom.ParseCycloneDXWithInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse CycloneDX output: %v", err)
	}

	if len(reparsed) != len(comps) {
		t.Errorf("Component count mismatch: original=%d, converted=%d", len(comps), len(reparsed))
	}

	origNames := make(map[string]bool)
	for _, c := range comps {
		origNames[c.Name] = true
	}
	for _, c := range reparsed {
		if !origNames[c.Name] {
			t.Errorf("Unexpected component name %q in converted output", c.Name)
		}
	}
}

func TestRealData_SyftPython_ToSPDX(t *testing.T) {
	path := testdataPath("real-syft-python.json")
	skipIfMissing(t, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	comps, info, err := sbom.ParseSyftWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse Syft: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed")
	}

	var buf bytes.Buffer
	if err := WriteSPDX(&buf, comps, info); err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	reparsed, err := sbom.ParseSPDXFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse SPDX output: %v", err)
	}

	if len(reparsed) != len(comps) {
		t.Errorf("Component count mismatch: original=%d, converted=%d", len(comps), len(reparsed))
	}
}

func TestRealData_OutputStructuralIntegrity(t *testing.T) {
	path := testdataPath("real-syft-alpine.json")
	skipIfMissing(t, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	comps, info, err := sbom.ParseSyftWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse Syft: %v", err)
	}

	t.Run("CDX_has_versions", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteCycloneDX(&buf, comps, info); err != nil {
			t.Fatalf("WriteCycloneDX failed: %v", err)
		}
		reparsed, _, err := sbom.ParseCycloneDXWithInfo(buf.Bytes())
		if err != nil {
			t.Fatalf("Reparse failed: %v", err)
		}
		versionCount := 0
		for _, c := range reparsed {
			if c.Version != "" {
				versionCount++
			}
		}
		if versionCount == 0 {
			t.Error("No components with versions in CDX output")
		}
	})

	t.Run("SPDX_has_versions", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteSPDX(&buf, comps, info); err != nil {
			t.Fatalf("WriteSPDX failed: %v", err)
		}
		reparsed, err := sbom.ParseSPDXFromBytes(buf.Bytes())
		if err != nil {
			t.Fatalf("Reparse failed: %v", err)
		}
		versionCount := 0
		for _, c := range reparsed {
			if c.Version != "" {
				versionCount++
			}
		}
		if versionCount == 0 {
			t.Error("No components with versions in SPDX output")
		}
	})

	t.Run("Syft_has_versions", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteSyft(&buf, comps, info); err != nil {
			t.Fatalf("WriteSyft failed: %v", err)
		}
		reparsed, err := sbom.ParseSyft(buf.Bytes())
		if err != nil {
			t.Fatalf("Reparse failed: %v", err)
		}
		versionCount := 0
		for _, c := range reparsed {
			if c.Version != "" {
				versionCount++
			}
		}
		if versionCount == 0 {
			t.Error("No components with versions in Syft output")
		}
	})
}
