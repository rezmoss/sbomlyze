package sbom

import (
	"os"
	"testing"
)

func TestParseSyft_BasicArtifacts(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 3 {
		t.Fatalf("expected 3 components, got %d", len(comps))
	}
	for _, c := range comps {
		if c.Name == "busybox" {
			if c.Version != "1.36.1-r15" {
				t.Errorf("expected busybox version 1.36.1-r15, got %s", c.Version)
			}
			if c.PURL != "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64" {
				t.Errorf("expected busybox PURL, got %s", c.PURL)
			}
			if c.Type != "apk" {
				t.Errorf("expected type=apk, got %s", c.Type)
			}
			if c.FoundBy != "apkdb-cataloger" {
				t.Errorf("expected foundBy=apkdb-cataloger, got %s", c.FoundBy)
			}
			return
		}
	}
	t.Error("busybox not found")
}

func TestParseSyft_Licenses(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "busybox" {
			if len(c.Licenses) != 1 || c.Licenses[0] != "GPL-2.0-only" {
				t.Errorf("expected licenses=[GPL-2.0-only], got %v", c.Licenses)
			}
			return
		}
	}
	t.Error("busybox not found")
}

func TestParseSyft_CPEs(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "busybox" {
			if len(c.CPEs) != 1 {
				t.Errorf("expected 1 CPE, got %d", len(c.CPEs))
			}
			if len(c.CPEs) > 0 && c.CPEs[0] != "cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*" {
				t.Errorf("unexpected CPE: %s", c.CPEs[0])
			}
			return
		}
	}
	t.Error("busybox not found")
}

func TestParseSyft_Dependencies(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.Name == "busybox" {
			if len(c.Dependencies) != 2 {
				t.Errorf("expected 2 dependencies, got %d: %v", len(c.Dependencies), c.Dependencies)
			}
			return
		}
	}
	t.Error("busybox not found")
}

func TestParseSyft_RawJSON(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if len(c.RawJSON) == 0 {
			t.Errorf("expected RawJSON populated for %s", c.Name)
		}
	}
}

func TestParseSyft_IDComputed(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		if c.ID == "" {
			t.Errorf("expected ID computed for %s", c.Name)
		}
	}
}

func TestParseSyft_MalformedArtifact(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-malformed-artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should skip the malformed string artifact and parse the 2 good ones
	if len(comps) != 2 {
		t.Errorf("expected 2 components (skipping malformed), got %d", len(comps))
	}
}

func TestParseSyft_EmptyArtifacts(t *testing.T) {
	comps, err := ParseSyft([]byte(`{"artifacts":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comps) != 0 {
		t.Errorf("expected 0 components, got %d", len(comps))
	}
}

func TestParseSyft_InvalidJSON(t *testing.T) {
	_, err := ParseSyft([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseSyftWithInfo_Source(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.SourceType != "image" {
		t.Errorf("expected SourceType=image, got %q", info.SourceType)
	}
	if info.SourceName != "alpine:latest" {
		t.Errorf("expected SourceName=alpine:latest, got %q", info.SourceName)
	}
}

func TestParseSyftWithInfo_DistroObject(t *testing.T) {
	data := []byte(`{
		"artifacts": [],
		"distro": {"name": "Ubuntu", "version": "22.04", "id": "ubuntu"}
	}`)
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.OSName != "Ubuntu" {
		t.Errorf("expected OSName=Ubuntu, got %q", info.OSName)
	}
	if info.OSVersion != "22.04" {
		t.Errorf("expected OSVersion=22.04, got %q", info.OSVersion)
	}
}

func TestParseSyftWithInfo_DistroArray(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-distro-array.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.OSName != "Alpine Linux" {
		t.Errorf("expected OSName='Alpine Linux', got %q", info.OSName)
	}
	if info.OSVersion != "3.19.0" {
		t.Errorf("expected OSVersion=3.19.0, got %q", info.OSVersion)
	}
}

func TestParseSyftWithInfo_DistroIDFallback(t *testing.T) {
	data := []byte(`{
		"artifacts": [],
		"distro": {"name": "", "version": "3.19", "id": "alpine"}
	}`)
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.OSName != "alpine" {
		t.Errorf("expected OSName=alpine (from id fallback), got %q", info.OSName)
	}
}

func TestParseSyftWithInfo_NoSource(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-no-source.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.SourceType != "" {
		t.Errorf("expected empty SourceType, got %q", info.SourceType)
	}
	if info.SourceName != "" {
		t.Errorf("expected empty SourceName, got %q", info.SourceName)
	}
}

func TestParseSyftWithInfo_NoDistro(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-no-source.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.OSName != "" {
		t.Errorf("expected empty OSName, got %q", info.OSName)
	}
	if info.OSVersion != "" {
		t.Errorf("expected empty OSVersion, got %q", info.OSVersion)
	}
}

func TestParseSyft_Language(t *testing.T) {
	data := []byte(`{
		"artifacts": [{
			"name": "requests",
			"version": "2.31.0",
			"type": "python",
			"language": "python",
			"foundBy": "python-package-cataloger",
			"purl": "pkg:pypi/requests@2.31.0"
		}]
	}`)
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if comps[0].Language != "python" {
		t.Errorf("expected language=python, got %q", comps[0].Language)
	}
	if comps[0].FoundBy != "python-package-cataloger" {
		t.Errorf("expected foundBy=python-package-cataloger, got %q", comps[0].FoundBy)
	}
}

