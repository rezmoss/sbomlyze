package sbom

import (
	"slices"
	"testing"
)

func TestLicenseTerms(t *testing.T) {
	cases := []struct {
		a, b []string
		same bool
	}{
		{[]string{"GPL-2.0-only", "GPL-2.0-or-later"}, []string{"GPL-2.0-only AND GPL-2.0-or-later"}, true},
		{[]string{"MPL-2.0 AND MIT"}, []string{"(MPL-2.0 AND MIT)"}, true},
		{[]string{"sha256:fd7e"}, []string{"LicenseRef-fd7e"}, true},
		{[]string{"Expat"}, []string{"LicenseRef-Expat"}, true},
		{[]string{"MIT/X11"}, []string{"LicenseRef-MIT-X11"}, true},
		{[]string{"GFDL-1.3+-no-invariant"}, []string{"LicenseRef-GFDL-1.3--no-invariant"}, true},
		{[]string{"mit"}, []string{"MIT"}, true},
		{[]string{"MIT OR Apache-2.0"}, []string{"MIT", "Apache-2.0"}, false},
		{[]string{"GPL-2.0-only WITH Classpath-exception-2.0"}, []string{"GPL-2.0-only"}, false},
		{[]string{"(MIT) OR (BSD-3-Clause)"}, []string{"MIT", "BSD-3-Clause"}, false},
		{[]string{"MIT"}, []string{"Apache-2.0"}, false},
		{[]string{"https://raw.githubusercontent.com/akka/akka/main/LICENSE;description=BUSL-1.1"}, []string{"BUSL-1.1"}, true},
		{[]string{"LicenseRef-https---raw.githubusercontent.com-akka-akka-main-LICENSE-description-BUSL-1.1"}, []string{"BUSL-1.1"}, true},
		{[]string{"https://www.apache.org/licenses/LICENSE-2.0.html;description=Apache-2.0"}, []string{"Apache-2.0"}, true},
		{[]string{"https://example.com/l;description=Some License Text"}, []string{"Some"}, false},
		// custom ref is not the expression it resembles
		{[]string{"MIT OR Apache-2.0"}, []string{"LicenseRef-MIT-OR-Apache-2.0"}, false},
		{[]string{"GPL-2.0-only WITH Classpath-exception-2.0"}, []string{"LicenseRef-GPL-2.0-only-WITH-Classpath-exception-2.0"}, false},
		{[]string{"MIT OR Apache-2.0"}, []string{"(mit OR LicenseRef-Apache-2.0)"}, true},
		// lowercase "and" is prose, not an operator
		{[]string{"Research and Development License"}, []string{"LicenseRef-Research-and-Development-License"}, true},
		{[]string{"Research and Development License"}, []string{"Research", "Development License"}, false},
		// free text: syft folds it into one SPDX LicenseRef
		{[]string{"Apache 2.0"}, []string{"LicenseRef-Apache-2.0"}, true},
		{[]string{"http://www.eclipse.org/legal/epl-v10.html, http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html"}, []string{"LicenseRef-http---www.eclipse.org-legal-epl-v10.html--http---www.gnu.org-licenses-old-licenses-lgpl-2.1.html"}, true},
	}
	for _, c := range cases {
		if got := SameLicenses(c.a, c.b); got != c.same {
			t.Errorf("SameLicenses(%q, %q) = %v (%v vs %v)", c.a, c.b, got, LicenseTerms(c.a), LicenseTerms(c.b))
		}
	}
	if n := LicenseTermNames([]string{"LicenseRef-Expat AND BSD-3-Clause"}); n["expat"] != "Expat" || n["bsd-3-clause"] != "BSD-3-Clause" {
		t.Errorf("display names: %v", n)
	}
	if got := LicenseTerms(nil); !slices.Equal(got, []string{}) && got != nil {
		t.Errorf("empty: %v", got)
	}
}

func TestSPDXSourceInfoPaths(t *testing.T) {
	got := spdxSourceInfoPaths("acquired package info from installed node module manifest file: /usr/lib/node_modules/a/package.json")
	if !slices.Equal(got, []string{"/usr/lib/node_modules/a/package.json"}) {
		t.Errorf("got %v", got)
	}
	if got := spdxSourceInfoPaths("acquired package info from the following paths: /a.jar, /b.jar"); !slices.Equal(got, []string{"/a.jar", "/b.jar"}) {
		t.Errorf("got %v", got)
	}
	if got := spdxSourceInfoPaths("built by someone"); got != nil {
		t.Errorf("non-syft sourceInfo: %v", got)
	}
}

func TestSPDXZeroChecksumIsAbsent(t *testing.T) {
	data := []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"x","documentNamespace":"https://x/y",
"creationInfo":{"created":"2025-01-01T00:00:00Z","creators":["Tool: syft-1.0.0"]},
"files":[{"fileName":"usr/lib/a.so","SPDXID":"SPDXRef-File-a","checksums":[{"algorithm":"SHA1","checksumValue":"0000000000000000000000000000000000000000"}]},
 {"fileName":"usr/lib/b.so","SPDXID":"SPDXRef-File-b","checksums":[{"algorithm":"SHA1","checksumValue":"15f935d0aa"}]}]}`)
	_, info, err := parseSPDXData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Files) != 2 || len(info.Files[0].Hashes) != 0 || info.Files[1].Hashes["SHA1"] != "15f935d0aa" {
		t.Errorf("got %+v", info.Files)
	}
}

func TestCycloneDXSyftPrimaryLocation(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"apt","version":"2.4.11",
"purl":"pkg:deb/ubuntu/apt@2.4.11","properties":[
 {"name":"syft:location:0:layerID","value":"sha256:aa"},{"name":"syft:location:0:path","value":"/var/lib/dpkg/status"},
 {"name":"syft:location:1:path","value":"/usr/share/doc/apt/copyright"}]}]}`)
	comps, _, err := ParseCycloneDXWithInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(comps[0].PrimaryLocations, []string{"/var/lib/dpkg/status"}) {
		t.Errorf("primary = %v", comps[0].PrimaryLocations)
	}
}

func TestLicenseIDsKeepsFullNames(t *testing.T) {
	ids := LicenseIDs([]string{"GNU General Public License v3.0 only"})
	if _, ok := ids[LicenseKey("GNU General Public License v3.0 only")]; !ok {
		t.Errorf("full name must match itself: %v", ids)
	}
	ids = LicenseIDs([]string{"MIT AND (GPL-3.0-only OR BSD-2-Clause)"})
	for _, id := range []string{"MIT", "GPL-3.0-only", "BSD-2-Clause"} {
		if _, ok := ids[LicenseKey(id)]; !ok {
			t.Errorf("missing %s in %v", id, ids)
		}
	}
}

func TestLicenseIDsIgnoreProse(t *testing.T) {
	ids := LicenseIDs([]string{"Acme Commercial License"})
	if _, ok := ids[LicenseKey("Acme")]; ok || len(ids) != 1 {
		t.Errorf("prose is one name, not ids: %v", ids)
	}
}
