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

func TestParseSyftWithInfo_Descriptor(t *testing.T) {
	data := []byte(`{
		"artifacts": [],
		"descriptor": {"name": "syft", "version": "0.98.0"},
		"schema": {"version": "16.0.15", "url": "https://example.com/schema.json"}
	}`)
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.ToolName != "syft" {
		t.Errorf("expected ToolName=syft, got %q", info.ToolName)
	}
	if info.ToolVersion != "0.98.0" {
		t.Errorf("expected ToolVersion=0.98.0, got %q", info.ToolVersion)
	}
	if info.SchemaVersion != "16.0.15" {
		t.Errorf("expected SchemaVersion=16.0.15, got %q", info.SchemaVersion)
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

func TestParseSyftWithInfo_DistroExtraFields(t *testing.T) {
	data := []byte(`{
		"artifacts": [],
		"distro": {
			"name": "Amazon Linux",
			"prettyName": "Amazon Linux 2",
			"version": "2",
			"id": "amzn",
			"idLike": ["centos", "rhel", "fedora"]
		}
	}`)
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.OSPrettyName != "Amazon Linux 2" {
		t.Errorf("expected OSPrettyName='Amazon Linux 2', got %q", info.OSPrettyName)
	}
	if len(info.OSIDLike) != 3 || info.OSIDLike[0] != "centos" {
		t.Errorf("expected OSIDLike=[centos rhel fedora], got %v", info.OSIDLike)
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

func TestParseSyft_Hashes(t *testing.T) {
	data, err := os.ReadFile(testdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		switch c.Name {
		case "busybox":
			// rpm-db-entry: metadata.files[0].digest
			if v, ok := c.Hashes["SHA256"]; !ok || v != "abc123def456" {
				t.Errorf("busybox: expected SHA256=abc123def456, got %v", c.Hashes)
			}
		case "musl":
			// java-archive: metadata.digest[]
			if v, ok := c.Hashes["SHA1"]; !ok || v != "deadbeef1234" {
				t.Errorf("musl: expected SHA1=deadbeef1234, got %v", c.Hashes)
			}
		case "alpine-baselayout":
			// no metadata — hashes should be empty
			if len(c.Hashes) != 0 {
				t.Errorf("alpine-baselayout: expected no hashes, got %v", c.Hashes)
			}
		}
	}
}

func TestParseSyft_HashesNPM(t *testing.T) {
	data := []byte(`{
		"artifacts": [{
			"name": "lodash",
			"version": "4.17.21",
			"purl": "pkg:npm/lodash@4.17.21",
			"metadataType": "javascript-npm-package-lock-entry",
			"metadata": {
				"integrity": "sha512-WFN04846+u76oB43base64data"
			}
		}]
	}`)
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if v, ok := comps[0].Hashes["SHA512"]; !ok || v != "WFN04846+u76oB43base64data" {
		t.Errorf("expected SHA512 hash from npm integrity, got %v", comps[0].Hashes)
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

