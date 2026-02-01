package analysis

import (
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestComputeStats(t *testing.T) {
	t.Run("counts components", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/a", Name: "a", Version: "1.0.0"},
			{ID: "pkg:npm/b", Name: "b", Version: "1.0.0"},
			{ID: "pkg:npm/c", Name: "c", Version: "1.0.0"},
		}

		stats := ComputeStats(comps)

		if stats.TotalComponents != 3 {
			t.Errorf("expected 3 components, got %d", stats.TotalComponents)
		}
	})

	t.Run("counts components by type", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/a", Name: "a"},
			{ID: "pkg:npm/b", Name: "b"},
			{ID: "pkg:apk/alpine/c", Name: "c"},
			{ID: "pkg:pypi/d", Name: "d"},
		}

		stats := ComputeStats(comps)

		if stats.ByType["npm"] != 2 {
			t.Errorf("expected 2 npm, got %d", stats.ByType["npm"])
		}
		if stats.ByType["apk"] != 1 {
			t.Errorf("expected 1 apk, got %d", stats.ByType["apk"])
		}
		if stats.ByType["pypi"] != 1 {
			t.Errorf("expected 1 pypi, got %d", stats.ByType["pypi"])
		}
	})

	t.Run("counts license distribution", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a", Licenses: []string{"MIT"}},
			{ID: "b", Name: "b", Licenses: []string{"MIT"}},
			{ID: "c", Name: "c", Licenses: []string{"Apache-2.0"}},
			{ID: "d", Name: "d", Licenses: []string{}},
		}

		stats := ComputeStats(comps)

		if stats.ByLicense["MIT"] != 2 {
			t.Errorf("expected 2 MIT, got %d", stats.ByLicense["MIT"])
		}
		if stats.ByLicense["Apache-2.0"] != 1 {
			t.Errorf("expected 1 Apache-2.0, got %d", stats.ByLicense["Apache-2.0"])
		}
		if stats.WithoutLicense != 1 {
			t.Errorf("expected 1 without license, got %d", stats.WithoutLicense)
		}
	})

	t.Run("counts hashes", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a", Hashes: map[string]string{"SHA256": "abc"}},
			{ID: "b", Name: "b", Hashes: map[string]string{}},
			{ID: "c", Name: "c"},
		}

		stats := ComputeStats(comps)

		if stats.WithHashes != 1 {
			t.Errorf("expected 1 with hashes, got %d", stats.WithHashes)
		}
		if stats.WithoutHashes != 2 {
			t.Errorf("expected 2 without hashes, got %d", stats.WithoutHashes)
		}
	})

	t.Run("counts dependencies", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a", Dependencies: []string{"b", "c"}},
			{ID: "b", Name: "b", Dependencies: []string{"c"}},
			{ID: "c", Name: "c"},
		}

		stats := ComputeStats(comps)

		if stats.TotalDependencies != 3 {
			t.Errorf("expected 3 total deps, got %d", stats.TotalDependencies)
		}
		if stats.WithDependencies != 2 {
			t.Errorf("expected 2 with deps, got %d", stats.WithDependencies)
		}
	})

	t.Run("detects duplicates", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/a", Name: "a", Version: "1.0.0"},
			{ID: "pkg:npm/a", Name: "a", Version: "2.0.0"},
			{ID: "pkg:npm/b", Name: "b", Version: "1.0.0"},
		}

		stats := ComputeStats(comps)

		if stats.DuplicateCount != 1 {
			t.Errorf("expected 1 duplicate group, got %d", stats.DuplicateCount)
		}
	})

	t.Run("handles empty input", func(t *testing.T) {
		stats := ComputeStats([]sbom.Component{})

		if stats.TotalComponents != 0 {
			t.Errorf("expected 0 components, got %d", stats.TotalComponents)
		}
	})

	t.Run("counts by language", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a", Language: "go"},
			{ID: "b", Name: "b", Language: "go"},
			{ID: "c", Name: "c", Language: "python"},
			{ID: "d", Name: "d"}, // no language
		}

		stats := ComputeStats(comps)

		if stats.ByLanguage["go"] != 2 {
			t.Errorf("expected 2 go, got %d", stats.ByLanguage["go"])
		}
		if stats.ByLanguage["python"] != 1 {
			t.Errorf("expected 1 python, got %d", stats.ByLanguage["python"])
		}
	})

	t.Run("counts by scanner/foundBy", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a", FoundBy: "go-module-cataloger"},
			{ID: "b", Name: "b", FoundBy: "go-module-cataloger"},
			{ID: "c", Name: "c", FoundBy: "python-cataloger"},
			{ID: "d", Name: "d"}, // no foundBy
		}

		stats := ComputeStats(comps)

		if stats.ByFoundBy["go-module-cataloger"] != 2 {
			t.Errorf("expected 2 go-module-cataloger, got %d", stats.ByFoundBy["go-module-cataloger"])
		}
		if stats.ByFoundBy["python-cataloger"] != 1 {
			t.Errorf("expected 1 python-cataloger, got %d", stats.ByFoundBy["python-cataloger"])
		}
	})

	t.Run("counts CPEs", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a", CPEs: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}},
			{ID: "b", Name: "b", CPEs: []string{}},
			{ID: "c", Name: "c"},
		}

		stats := ComputeStats(comps)

		if stats.WithCPEs != 1 {
			t.Errorf("expected 1 with CPEs, got %d", stats.WithCPEs)
		}
		if stats.WithoutCPEs != 2 {
			t.Errorf("expected 2 without CPEs, got %d", stats.WithoutCPEs)
		}
	})

	t.Run("counts PURLs", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a", PURL: "pkg:npm/a@1.0.0"},
			{ID: "b", Name: "b", PURL: "pkg:npm/b@1.0.0"},
			{ID: "c", Name: "c"},
		}

		stats := ComputeStats(comps)

		if stats.WithPURL != 2 {
			t.Errorf("expected 2 with PURL, got %d", stats.WithPURL)
		}
		if stats.WithoutPURL != 1 {
			t.Errorf("expected 1 without PURL, got %d", stats.WithoutPURL)
		}
	})

	t.Run("categorizes licenses", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a", Licenses: []string{"GPL-3.0"}},
			{ID: "b", Name: "b", Licenses: []string{"MIT"}},
			{ID: "c", Name: "c", Licenses: []string{"Apache-2.0"}},
			{ID: "d", Name: "d", Licenses: []string{"public-domain"}},
			{ID: "e", Name: "e", Licenses: []string{"Unknown-License"}},
			{ID: "f", Name: "f"}, // no license
		}

		stats := ComputeStats(comps)

		if stats.LicenseCategories == nil {
			t.Fatal("expected license categories to be set")
		}
		if stats.LicenseCategories.Copyleft != 1 {
			t.Errorf("expected 1 copyleft, got %d", stats.LicenseCategories.Copyleft)
		}
		if stats.LicenseCategories.Permissive != 2 {
			t.Errorf("expected 2 permissive, got %d", stats.LicenseCategories.Permissive)
		}
		if stats.LicenseCategories.PublicDomain != 1 {
			t.Errorf("expected 1 public domain, got %d", stats.LicenseCategories.PublicDomain)
		}
		// Unknown-License + no license = 2 unknown
		if stats.LicenseCategories.Unknown != 2 {
			t.Errorf("expected 2 unknown, got %d", stats.LicenseCategories.Unknown)
		}
	})

	t.Run("handles missing optional fields gracefully", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "a", Name: "a"}, // minimal component
		}

		stats := ComputeStats(comps)

		// Should not panic and should have sensible defaults
		if stats.TotalComponents != 1 {
			t.Errorf("expected 1 component, got %d", stats.TotalComponents)
		}
		if stats.ByLanguage != nil {
			t.Errorf("expected nil ByLanguage for no language data, got %v", stats.ByLanguage)
		}
		if stats.ByFoundBy != nil {
			t.Errorf("expected nil ByFoundBy for no foundBy data, got %v", stats.ByFoundBy)
		}
	})
}

func TestExtractPURLType(t *testing.T) {
	tests := []struct {
		purl     string
		expected string
	}{
		{"pkg:npm/lodash@1.0.0", "npm"},
		{"pkg:apk/alpine/nginx@1.0.0", "apk"},
		{"pkg:pypi/requests@2.0.0", "pypi"},
		{"pkg:maven/org.apache/commons@1.0", "maven"},
		{"pkg:golang/github.com/user/repo@1.0", "golang"},
		{"", "unknown"},
		{"not-a-purl", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			result := ExtractPURLType(tt.purl)
			if result != tt.expected {
				t.Errorf("ExtractPURLType(%q) = %q, want %q", tt.purl, result, tt.expected)
			}
		})
	}
}

func TestCategorizeLicense(t *testing.T) {
	tests := []struct {
		license  string
		expected string
	}{
		// Copyleft licenses
		{"GPL-2.0", "copyleft"},
		{"GPL-3.0", "copyleft"},
		{"LGPL-2.1", "copyleft"},
		{"AGPL-3.0", "copyleft"},
		{"MPL-2.0", "copyleft"},
		{"EPL-1.0", "copyleft"},
		{"gpl-2.0", "copyleft"}, // case insensitive

		// Permissive licenses
		{"MIT", "permissive"},
		{"BSD-3-Clause", "permissive"},
		{"BSD-2-Clause", "permissive"},
		{"Apache-2.0", "permissive"},
		{"ISC", "permissive"},
		{"Zlib", "permissive"},
		{"Expat", "permissive"},
		{"mit", "permissive"}, // case insensitive

		// Public domain
		{"public-domain", "public_domain"},
		{"Public Domain", "public_domain"},
		{"PUBLICDOMAIN", "public_domain"},

		// Unknown
		{"Unknown", "unknown"},
		{"Proprietary", "unknown"},
		{"", "unknown"},
		{"Some-Custom-License", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			result := CategorizeLicense(tt.license)
			if result != tt.expected {
				t.Errorf("CategorizeLicense(%q) = %q, want %q", tt.license, result, tt.expected)
			}
		})
	}
}
