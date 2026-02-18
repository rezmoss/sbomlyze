package convert

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func testdataPath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func TestRoundTrip_CDX_to_SPDX(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	comps, info, err := sbom.ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse CycloneDX: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed from CycloneDX")
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
		t.Errorf("Component count mismatch: original=%d, roundtrip=%d", len(comps), len(reparsed))
	}

	nameMap := make(map[string]bool)
	for _, c := range reparsed {
		nameMap[c.Name] = true
	}
	for _, c := range comps {
		if !nameMap[c.Name] {
			t.Errorf("Component %q lost during roundtrip", c.Name)
		}
	}
}

func TestRoundTrip_CDX_to_Syft(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	comps, info, err := sbom.ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse CycloneDX: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed from CycloneDX")
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
		t.Errorf("Component count mismatch: original=%d, roundtrip=%d", len(comps), len(reparsed))
	}
}

func TestRoundTrip_SPDX_to_CDX(t *testing.T) {
	comps, err := sbom.ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatalf("Failed to parse SPDX: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed from SPDX")
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
		t.Errorf("Component count mismatch: original=%d, roundtrip=%d", len(comps), len(reparsed))
	}
}

func TestRoundTrip_SPDX_to_Syft(t *testing.T) {
	comps, err := sbom.ParseSPDX(testdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatalf("Failed to parse SPDX: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed from SPDX")
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
		t.Errorf("Component count mismatch: original=%d, roundtrip=%d", len(comps), len(reparsed))
	}
}

func TestRoundTrip_Syft_to_CDX(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	comps, info, err := sbom.ParseSyftWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse Syft: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed from Syft")
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
		t.Errorf("Component count mismatch: original=%d, roundtrip=%d", len(comps), len(reparsed))
	}
}

func TestRoundTrip_Syft_to_SPDX(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	comps, info, err := sbom.ParseSyftWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse Syft: %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("No components parsed from Syft")
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
		t.Errorf("Component count mismatch: original=%d, roundtrip=%d", len(comps), len(reparsed))
	}
}

func TestRoundTrip_ComponentCount(t *testing.T) {
	type roundtripCase struct {
		name       string
		sourceFile string
		parseFunc  func(t *testing.T) ([]sbom.Component, sbom.SBOMInfo)
		targetFmt  Format
		reparse    func(t *testing.T, data []byte) int
	}

	parseCDX := func(file string) func(t *testing.T) ([]sbom.Component, sbom.SBOMInfo) {
		return func(t *testing.T) ([]sbom.Component, sbom.SBOMInfo) {
			t.Helper()
			data, err := os.ReadFile(testdataPath(file))
			if err != nil {
				t.Fatalf("Failed to read %s: %v", file, err)
			}
			comps, info, err := sbom.ParseCycloneDXWithInfo(data)
			if err != nil {
				t.Fatalf("Failed to parse CDX %s: %v", file, err)
			}
			return comps, info
		}
	}

	parseSPDX := func(file string) func(t *testing.T) ([]sbom.Component, sbom.SBOMInfo) {
		return func(t *testing.T) ([]sbom.Component, sbom.SBOMInfo) {
			t.Helper()
			comps, err := sbom.ParseSPDX(testdataPath(file))
			if err != nil {
				t.Fatalf("Failed to parse SPDX %s: %v", file, err)
			}
			return comps, sbom.SBOMInfo{}
		}
	}

	parseSyft := func(file string) func(t *testing.T) ([]sbom.Component, sbom.SBOMInfo) {
		return func(t *testing.T) ([]sbom.Component, sbom.SBOMInfo) {
			t.Helper()
			data, err := os.ReadFile(testdataPath(file))
			if err != nil {
				t.Fatalf("Failed to read %s: %v", file, err)
			}
			comps, info, err := sbom.ParseSyftWithInfo(data)
			if err != nil {
				t.Fatalf("Failed to parse Syft %s: %v", file, err)
			}
			return comps, info
		}
	}

	reparseCDX := func(t *testing.T, data []byte) int {
		t.Helper()
		comps, _, err := sbom.ParseCycloneDXWithInfo(data)
		if err != nil {
			t.Fatalf("Failed to reparse CDX: %v", err)
		}
		return len(comps)
	}

	reparseSPDX := func(t *testing.T, data []byte) int {
		t.Helper()
		comps, err := sbom.ParseSPDXFromBytes(data)
		if err != nil {
			t.Fatalf("Failed to reparse SPDX: %v", err)
		}
		return len(comps)
	}

	reparseSyft := func(t *testing.T, data []byte) int {
		t.Helper()
		comps, err := sbom.ParseSyft(data)
		if err != nil {
			t.Fatalf("Failed to reparse Syft: %v", err)
		}
		return len(comps)
	}

	cases := []roundtripCase{
		{"CDX->SPDX", "cyclonedx-before.json", parseCDX("cyclonedx-before.json"), FormatSPDX, reparseSPDX},
		{"CDX->Syft", "cyclonedx-before.json", parseCDX("cyclonedx-before.json"), FormatSyft, reparseSyft},
		{"SPDX->CDX", "spdx-sample.json", parseSPDX("spdx-sample.json"), FormatCycloneDX, reparseCDX},
		{"SPDX->Syft", "spdx-sample.json", parseSPDX("spdx-sample.json"), FormatSyft, reparseSyft},
		{"Syft->CDX", "syft-sample.json", parseSyft("syft-sample.json"), FormatCycloneDX, reparseCDX},
		{"Syft->SPDX", "syft-sample.json", parseSyft("syft-sample.json"), FormatSPDX, reparseSPDX},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			comps, info := tc.parseFunc(t)
			if len(comps) == 0 {
				t.Skip("No components parsed from source")
			}

			var buf bytes.Buffer
			if err := Convert(&buf, comps, info, tc.targetFmt); err != nil {
				t.Fatalf("Convert failed: %v", err)
			}

			count := tc.reparse(t, buf.Bytes())
			if count != len(comps) {
				t.Errorf("Component count mismatch: original=%d, roundtrip=%d", len(comps), count)
			}
		})
	}
}

func TestRoundTrip_FieldPreservation(t *testing.T) {
	data, err := os.ReadFile(testdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	origComps, info, err := sbom.ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatalf("Failed to parse CDX: %v", err)
	}

	var spdxBuf bytes.Buffer
	if err := WriteSPDX(&spdxBuf, origComps, info); err != nil {
		t.Fatalf("WriteSPDX failed: %v", err)
	}

	spdxComps, err := sbom.ParseSPDXFromBytes(spdxBuf.Bytes())
	if err != nil {
		t.Fatalf("Failed to parse SPDX output: %v", err)
	}

	var cdxBuf bytes.Buffer
	if err := WriteCycloneDX(&cdxBuf, spdxComps, info); err != nil {
		t.Fatalf("WriteCycloneDX failed: %v", err)
	}

	finalComps, _, err := sbom.ParseCycloneDXWithInfo(cdxBuf.Bytes())
	if err != nil {
		t.Fatalf("Failed to parse final CDX output: %v", err)
	}

	if len(finalComps) != len(origComps) {
		t.Fatalf("Component count mismatch after double roundtrip: original=%d, final=%d", len(origComps), len(finalComps))
	}

	origByName := make(map[string]sbom.Component)
	for _, c := range origComps {
		origByName[c.Name] = c
	}
	finalByName := make(map[string]sbom.Component)
	for _, c := range finalComps {
		finalByName[c.Name] = c
	}

	for name, orig := range origByName {
		final, ok := finalByName[name]
		if !ok {
			t.Errorf("Component %q lost after double roundtrip", name)
			continue
		}
		if orig.Version != final.Version {
			t.Errorf("Component %q version mismatch: orig=%q, final=%q", name, orig.Version, final.Version)
		}
		if orig.PURL != "" && orig.PURL != final.PURL {
			t.Errorf("Component %q PURL mismatch: orig=%q, final=%q", name, orig.PURL, final.PURL)
		}
	}
}
