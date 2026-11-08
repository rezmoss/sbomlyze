package sbom

import (
	"slices"
	"testing"
)

func TestParseCycloneDX_LocationsDigestsLicenseNames(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
	 "metadata":{"tools":{"components":[{"type":"application","name":"syft","version":"1.57.0"}]}},
	 "components":[
	  {"type":"library","name":"github.com/Microsoft/go-winio","version":"v0.6.2",
	   "purl":"pkg:golang/github.com/Microsoft/go-winio@v0.6.2",
	   "licenses":[{"license":{"name":"SEE LICENSE IN README"}}],
	   "properties":[
	    {"name":"syft:location:1:path","value":"/b/go.mod"},
	    {"name":"syft:metadata:h1Digest","value":"h1:abc="},
	    {"name":"syft:location:0:path","value":"/a/go.mod"},
	    {"name":"sbomlyze:location","value":"/c/go.mod"}],
	   "evidence":{"occurrences":[{"location":"/d/go.mod"},{"location":"/a/go.mod"}]}},
	  {"type":"library","name":"setup","version":"v0.9.6","purl":"pkg:github/anchore/go-make@v0.9.6#.github/actions/setup"}
	 ]}`)
	comps, info, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "CycloneDX" || info.SpecVersion != "1.6" || info.ToolName != "syft" {
		t.Errorf("info = %+v", info)
	}
	c := NormalizeComponent(comps[0])
	if want := []string{"/a/go.mod", "/b/go.mod", "/c/go.mod", "/d/go.mod"}; !slices.Equal(c.Locations, want) {
		t.Errorf("locations = %v, want %v", c.Locations, want)
	}
	if c.Digests[DigestGoH1] != "h1:abc=" {
		t.Errorf("digests = %v", c.Digests)
	}
	if c.Name != "github.com/Microsoft/go-winio" {
		t.Errorf("declared case lost: %s", c.Name)
	}
	if !slices.Equal(c.Licenses, []string{"SEE LICENSE IN README"}) || !slices.Equal(c.NonSPDXLicenses, c.Licenses) {
		t.Errorf("licenses = %v non-spdx = %v", c.Licenses, c.NonSPDXLicenses)
	}
	if comps[1].ID != "pkg:github/anchore/go-make#.github/actions/setup" {
		t.Errorf("subpath dropped from ID: %s", comps[1].ID)
	}
}

func TestParseSyft_GoAndCargoDigests(t *testing.T) {
	data := []byte(`{"artifacts":[
	  {"id":"1","name":"golang.org/x/sys","version":"v0.49.0","type":"go-module","purl":"pkg:golang/golang.org/x/sys@v0.49.0",
	   "metadataType":"go-module-entry","metadata":{"h1Digest":"h1:sys="}},
	  {"id":"2","name":"serde","version":"1.0.0","type":"rust-crate","purl":"pkg:cargo/serde@1.0.0",
	   "metadataType":"rust-cargo-lock-entry","metadata":{"checksum":"abc"}},
	  {"id":"3","name":"other","version":"1.0.0","type":"npm","purl":"pkg:npm/other@1.0.0",
	   "metadataType":"something-else","metadata":{"checksum":"ignored"}}],
	 "source":{"type":"directory","target":{"userInput":"."}},
	 "descriptor":{"name":"syft","version":"1.57.0"},"schema":{"version":"16.0.0"}}`)
	comps, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "Syft JSON" || info.SpecVersion != "16.0.0" {
		t.Errorf("info = %+v", info)
	}
	if comps[0].Digests[DigestGoH1] != "h1:sys=" || comps[1].Digests[DigestCargoChecksum] != "abc" || comps[2].Digests != nil {
		t.Errorf("digests = %v / %v / %v", comps[0].Digests, comps[1].Digests, comps[2].Digests)
	}
}
