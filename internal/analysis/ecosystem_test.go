package analysis

import (
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestEcosystem(t *testing.T) {
	cpe := "cpe:2.3:a:grep-cli_project:grep-cli:0.1.11:*:*:*:*:rust:*:*"
	for _, tc := range []struct {
		name string
		c    sbom.Component
		want string
	}{
		{"purl wins", sbom.Component{PURL: "pkg:npm/x@1", PkgType: "rust-crate"}, "npm"},
		{"syft type (Syft JSON, CDX)", sbom.Component{PkgType: "rust-crate"}, "cargo"},
		{"cpe target_sw (SPDX)", sbom.Component{CPEs: []string{cpe}}, "cargo"},
		{"lockfile", sbom.Component{Locations: []string{"/sub/Cargo.lock"}}, "cargo"},
		{"go.mod", sbom.Component{Locations: []string{"/go.mod"}}, "golang"},
		{"cpe without target_sw", sbom.Component{CPEs: []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}}, "unknown"},
		{"nothing", sbom.Component{Name: "x"}, "unknown"},
	} {
		if got := Ecosystem(tc.c); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}
