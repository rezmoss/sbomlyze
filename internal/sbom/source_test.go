package sbom

import "testing"

func TestCycloneDXImageSourceAndOS(t *testing.T) {
	doc := func(ver, digest string) []byte {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"x","type":"container","name":"nginx","version":"` + digest + `"}},
"components":[{"bom-ref":"os:debian@` + ver + `","type":"operating-system","name":"debian","version":"` + ver + `","description":"Debian GNU/Linux 12 (bookworm)",
"properties":[{"name":"syft:distro:prettyName","value":"Debian GNU/Linux 12 (bookworm)"}]}]}`)
	}
	bc, bi, err := ParseCycloneDXWithInfo(doc("12.10", "sha256:aaa"))
	if err != nil {
		t.Fatal(err)
	}
	ac, _, err := ParseCycloneDXWithInfo(doc("12.12", "sha256:bbb"))
	if err != nil {
		t.Fatal(err)
	}
	if bc[0].ID != ac[0].ID || bc[0].ID != "os:debian" {
		t.Errorf("OS identity must not embed the version: %q vs %q", bc[0].ID, ac[0].ID)
	}
	if bi.SourceName != "nginx" || bi.SourceType != "container" || bi.SourceVersion != "sha256:aaa" {
		t.Errorf("container is the source: %+v", bi)
	}
	if bi.OSName != "debian" || bi.OSVersionID != "12.10" || bi.OSPrettyName != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("OS from operating-system component: %+v", bi)
	}
}

func TestSPDXImageRootIsSource(t *testing.T) {
	data := []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"nginx","documentNamespace":"https://x/y",
"creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: syft-1.0.0"]},
"packages":[
 {"name":"nginx","SPDXID":"SPDXRef-DocumentRoot-Image-nginx","versionInfo":"sha256:aaa","downloadLocation":"NOASSERTION"},
 {"name":"libc6","SPDXID":"SPDXRef-Package-deb-libc6","versionInfo":"2.36-9","downloadLocation":"NOASSERTION"}],
"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Image-nginx","relationshipType":"DESCRIBES"}]}`)
	comps, info, err := parseSPDXData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 || comps[0].Name != "libc6" {
		t.Errorf("image root must not be a package: %+v", comps)
	}
	if info.SourceName != "nginx" || info.SourceType != "image" || info.SourceVersion != "sha256:aaa" {
		t.Errorf("got %+v", info)
	}
}

func TestSPDXDescribedProductStaysPackage(t *testing.T) {
	data := []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"app","documentNamespace":"https://x/y",
"creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: x"]},
"packages":[{"name":"app","SPDXID":"SPDXRef-app","versionInfo":"1.2.0","downloadLocation":"NOASSERTION"}],
"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-app","relationshipType":"DESCRIBES"}]}`)
	comps, _, err := parseSPDXData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 {
		t.Errorf("described product is a real package: %+v", comps)
	}
}

func TestSyftDistroVersionIDAndSourceVersion(t *testing.T) {
	data := []byte(`{"artifacts":[],"source":{"id":"x","name":"nginx","version":"sha256:aaa","type":"image"},
"distro":{"prettyName":"Debian GNU/Linux 12 (bookworm)","name":"Debian GNU/Linux","id":"debian","version":"12 (bookworm)","versionID":"12.10"},
"descriptor":{"name":"syft","version":"1.0.0"},"schema":{"version":"16.0.0"}}`)
	_, info, err := ParseSyftWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.OSVersionID != "12.10" || info.SourceVersion != "sha256:aaa" {
		t.Errorf("got %+v", info)
	}
}

func TestSPDXOCIDescribedRootIsSource(t *testing.T) {
	data := []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"img","documentNamespace":"https://x/y",
"creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: trivy"]},
"packages":[{"name":"img","SPDXID":"SPDXRef-root","versionInfo":"sha256:aaa","downloadLocation":"NOASSERTION",
 "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:oci/img@sha256%3Aaaa"}]}],
"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-root","relationshipType":"DESCRIBES"}]}`)
	comps, info, err := parseSPDXData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 0 || info.SourceType != "image" || info.SourceVersion != "sha256:aaa" {
		t.Errorf("comps %+v info %+v", comps, info)
	}
}
