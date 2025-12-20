package main

import "testing"

func TestComputeStats(t *testing.T) {
	t.Run("counts components", func(t *testing.T) {
		comps := []Component{
			{ID: "pkg:npm/a", Name: "a", Version: "1.0.0"},
			{ID: "pkg:npm/b", Name: "b", Version: "1.0.0"},
			{ID: "pkg:npm/c", Name: "c", Version: "1.0.0"},
		}

		stats := computeStats(comps)

		if stats.TotalComponents != 3 {
			t.Errorf("expected 3 components, got %d", stats.TotalComponents)
		}
	})

	t.Run("counts components by type", func(t *testing.T) {
		comps := []Component{
			{ID: "pkg:npm/a", Name: "a"},
			{ID: "pkg:npm/b", Name: "b"},
			{ID: "pkg:apk/alpine/c", Name: "c"},
			{ID: "pkg:pypi/d", Name: "d"},
		}

		stats := computeStats(comps)

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
		comps := []Component{
			{ID: "a", Name: "a", Licenses: []string{"MIT"}},
			{ID: "b", Name: "b", Licenses: []string{"MIT"}},
			{ID: "c", Name: "c", Licenses: []string{"Apache-2.0"}},
			{ID: "d", Name: "d", Licenses: []string{}},
		}

		stats := computeStats(comps)

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
		comps := []Component{
			{ID: "a", Name: "a", Hashes: map[string]string{"SHA256": "abc"}},
			{ID: "b", Name: "b", Hashes: map[string]string{}},
			{ID: "c", Name: "c"},
		}

		stats := computeStats(comps)

		if stats.WithHashes != 1 {
			t.Errorf("expected 1 with hashes, got %d", stats.WithHashes)
		}
		if stats.WithoutHashes != 2 {
			t.Errorf("expected 2 without hashes, got %d", stats.WithoutHashes)
		}
	})

	t.Run("counts dependencies", func(t *testing.T) {
		comps := []Component{
			{ID: "a", Name: "a", Dependencies: []string{"b", "c"}},
			{ID: "b", Name: "b", Dependencies: []string{"c"}},
			{ID: "c", Name: "c"},
		}

		stats := computeStats(comps)

		if stats.TotalDependencies != 3 {
			t.Errorf("expected 3 total deps, got %d", stats.TotalDependencies)
		}
		if stats.WithDependencies != 2 {
			t.Errorf("expected 2 with deps, got %d", stats.WithDependencies)
		}
	})

	t.Run("detects duplicates", func(t *testing.T) {
		comps := []Component{
			{ID: "pkg:npm/a", Name: "a", Version: "1.0.0"},
			{ID: "pkg:npm/a", Name: "a", Version: "2.0.0"},
			{ID: "pkg:npm/b", Name: "b", Version: "1.0.0"},
		}

		stats := computeStats(comps)

		if stats.DuplicateCount != 1 {
			t.Errorf("expected 1 duplicate group, got %d", stats.DuplicateCount)
		}
	})

	t.Run("handles empty input", func(t *testing.T) {
		stats := computeStats([]Component{})

		if stats.TotalComponents != 0 {
			t.Errorf("expected 0 components, got %d", stats.TotalComponents)
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
			result := extractPURLType(tt.purl)
			if result != tt.expected {
				t.Errorf("extractPURLType(%q) = %q, want %q", tt.purl, result, tt.expected)
			}
		})
	}
}
