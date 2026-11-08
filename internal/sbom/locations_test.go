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

func TestParseFileInventoryAndOwnership(t *testing.T) {
	syftData := []byte(`{"artifacts":[
	  {"id":"p1","name":"adduser","version":"3.134","type":"deb","purl":"pkg:deb/debian/adduser@3.134",
	   "metadataType":"dpkg-db-entry","metadata":{"files":[{"path":"/etc/adduser.conf","isConfigFile":true},{"path":"/usr/sbin/adduser"}]}}],
	 "files":[
	  {"id":"f1","location":{"path":"/etc/adduser.conf","layerID":"sha256:l1"},"digests":[{"algorithm":"sha256","value":"aa"}]},
	  {"id":"f2","location":{"path":"/usr/sbin/adduser"},"digests":[{"algorithm":"sha1","value":"bb"}]},
	  {"id":"f3","location":{"path":"/go.mod"},"digests":[{"algorithm":"sha1","value":"cc"}]}],
	 "artifactRelationships":[
	  {"parent":"p1","child":"f1","type":"contains"},{"parent":"p1","child":"f2","type":"contains"},
	  {"parent":"p1","child":"f3","type":"evident-by"},{"parent":"src","child":"p1","type":"contains"}],
	 "descriptor":{"name":"syft"},"schema":{"version":"16.0.0"}}`)
	comps, info, err := ParseSyftWithInfo(syftData)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Files) != 3 || info.Files[0].Layer != "sha256:l1" {
		t.Errorf("files = %+v", info.Files)
	}
	c := NormalizeComponent(comps[0])
	if !slices.Equal(c.OwnedFiles, []string{"/etc/adduser.conf", "/usr/sbin/adduser"}) {
		t.Errorf("owned = %v (evident-by is not ownership)", c.OwnedFiles)
	}
	if !c.ConfigKnown || !slices.Equal(c.ConfigFiles, []string{"/etc/adduser.conf"}) {
		t.Errorf("config = %v known=%v", c.ConfigFiles, c.ConfigKnown)
	}

	spdxData := []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"x","documentNamespace":"https://x",
	 "creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: syft-1.57.0"]},
	 "packages":[{"name":"img","SPDXID":"SPDXRef-root","versionInfo":"sha256:x","downloadLocation":"NOASSERTION"},
	             {"name":"busybox","SPDXID":"SPDXRef-bb","versionInfo":"1.36.1-r31","downloadLocation":"NOASSERTION"}],
	 "files":[{"fileName":"bin/busybox","SPDXID":"SPDXRef-File-bb","checksums":[{"algorithm":"SHA256","checksumValue":"dd"}]}],
	 "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-root","relationshipType":"DESCRIBES"},
	   {"spdxElementId":"SPDXRef-root","relatedSpdxElement":"SPDXRef-File-bb","relationshipType":"CONTAINS"},
	   {"spdxElementId":"SPDXRef-bb","relatedSpdxElement":"SPDXRef-File-bb","relationshipType":"CONTAINS"}]}`)
	comps, info, err = ParseDataWithInfo(spdxData)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Files) != 1 || info.Files[0].Path != "/bin/busybox" || info.Files[0].Hashes["SHA256"] != "dd" {
		t.Errorf("spdx files = %+v", info.Files)
	}
	for _, c := range comps {
		switch c.Name {
		case "img":
			if len(c.OwnedFiles) != 0 {
				t.Errorf("the described root does not own files: %v", c.OwnedFiles)
			}
		case "busybox":
			if !slices.Equal(c.OwnedFiles, []string{"/bin/busybox"}) {
				t.Errorf("busybox owned = %v", c.OwnedFiles)
			}
		}
	}
}

func TestParseCycloneDX_SyftPackageType(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
	  {"type":"library","name":"zizmor","version":"1.32.0","cpe":"cpe:2.3:a:zizmor_project:zizmor:1.32.0:*:*:*:*:rust:*:*",
	   "properties":[{"name":"syft:package:type","value":"rust-crate"},{"name":"syft:location:0:path","value":"/Cargo.lock"}]}]}`)
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatal(err)
	}
	if c := NormalizeComponent(comps[0]); c.PkgType != "rust-crate" {
		t.Errorf("PkgType = %q", c.PkgType)
	}
}
