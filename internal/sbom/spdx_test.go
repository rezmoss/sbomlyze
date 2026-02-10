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
