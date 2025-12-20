package main

import (
	"testing"
)

func TestNormalizePURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "full purl with version, qualifiers, subpath",
			input:    "pkg:apk/alpine/nginx@1.27.3-r1?arch=aarch64&distro=alpine-3.20.5#subpath",
			expected: "pkg:apk/alpine/nginx",
		},
		{
			name:     "purl with version and qualifiers",
			input:    "pkg:apk/alpine/nginx@1.27.3-r1?arch=aarch64&distro=alpine-3.20.5",
			expected: "pkg:apk/alpine/nginx",
		},
		{
			name:     "purl with version only",
			input:    "pkg:npm/@babel/core@7.12.0",
			expected: "pkg:npm/@babel/core",
		},
		{
			name:     "purl without version",
			input:    "pkg:apk/alpine/nginx",
			expected: "pkg:apk/alpine/nginx",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "purl with encoded characters",
			input:    "pkg:apk/alpine/libstdc%2B%2B@15.2.0-r2?arch=aarch64",
			expected: "pkg:apk/alpine/libstdc%2B%2B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePURL(tt.input)
			if result != tt.expected {
				t.Errorf("normalizePURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractPURLVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "purl with version and qualifiers",
			input:    "pkg:apk/alpine/nginx@1.27.3-r1?arch=aarch64",
			expected: "1.27.3-r1",
		},
		{
			name:     "purl with version only",
			input:    "pkg:npm/@babel/core@7.12.0",
			expected: "7.12.0",
		},
		{
			name:     "purl without version",
			input:    "pkg:apk/alpine/nginx",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPURLVersion(tt.input)
			if result != tt.expected {
				t.Errorf("extractPURLVersion(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDiffComponents(t *testing.T) {
	t.Run("detects added components", func(t *testing.T) {
		before := []Component{}
		after := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
		}

		result := diffComponents(before, after)

		if len(result.Added) != 1 {
			t.Errorf("expected 1 added, got %d", len(result.Added))
		}
		if len(result.Removed) != 0 {
			t.Errorf("expected 0 removed, got %d", len(result.Removed))
		}
		if len(result.Changed) != 0 {
			t.Errorf("expected 0 changed, got %d", len(result.Changed))
		}
	})

	t.Run("detects removed components", func(t *testing.T) {
		before := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
		}
		after := []Component{}

		result := diffComponents(before, after)

		if len(result.Added) != 0 {
			t.Errorf("expected 0 added, got %d", len(result.Added))
		}
		if len(result.Removed) != 1 {
			t.Errorf("expected 1 removed, got %d", len(result.Removed))
		}
	})

	t.Run("detects version changes", func(t *testing.T) {
		before := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20"},
		}
		after := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
		}

		result := diffComponents(before, after)

		if len(result.Added) != 0 {
			t.Errorf("expected 0 added, got %d", len(result.Added))
		}
		if len(result.Removed) != 0 {
			t.Errorf("expected 0 removed, got %d", len(result.Removed))
		}
		if len(result.Changed) != 1 {
			t.Errorf("expected 1 changed, got %d", len(result.Changed))
		}
		if len(result.Changed) > 0 && result.Changed[0].Changes[0] != "version: 4.17.20 -> 4.17.21" {
			t.Errorf("unexpected change: %v", result.Changed[0].Changes)
		}
	})

	t.Run("detects license changes", func(t *testing.T) {
		before := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21", Licenses: []string{"MIT"}},
		}
		after := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21", Licenses: []string{"Apache-2.0"}},
		}

		result := diffComponents(before, after)

		if len(result.Changed) != 1 {
			t.Errorf("expected 1 changed, got %d", len(result.Changed))
		}
	})

	t.Run("detects hash changes", func(t *testing.T) {
		before := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21", Hashes: map[string]string{"SHA256": "abc123"}},
		}
		after := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21", Hashes: map[string]string{"SHA256": "def456"}},
		}

		result := diffComponents(before, after)

		if len(result.Changed) != 1 {
			t.Errorf("expected 1 changed, got %d", len(result.Changed))
		}
	})

	t.Run("no changes for identical components", func(t *testing.T) {
		before := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21", Licenses: []string{"MIT"}},
		}
		after := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21", Licenses: []string{"MIT"}},
		}

		result := diffComponents(before, after)

		if len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Changed) != 0 {
			t.Errorf("expected no differences, got added=%d removed=%d changed=%d",
				len(result.Added), len(result.Removed), len(result.Changed))
		}
	})
}

func TestEqualSlices(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "equal slices same order",
			a:        []string{"MIT", "Apache-2.0"},
			b:        []string{"MIT", "Apache-2.0"},
			expected: true,
		},
		{
			name:     "equal slices different order",
			a:        []string{"Apache-2.0", "MIT"},
			b:        []string{"MIT", "Apache-2.0"},
			expected: true,
		},
		{
			name:     "different lengths",
			a:        []string{"MIT"},
			b:        []string{"MIT", "Apache-2.0"},
			expected: false,
		},
		{
			name:     "different contents",
			a:        []string{"MIT"},
			b:        []string{"Apache-2.0"},
			expected: false,
		},
		{
			name:     "both empty",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := equalSlices(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("equalSlices(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestCompareComponents(t *testing.T) {
	t.Run("detects all change types", func(t *testing.T) {
		before := Component{
			ID:       "pkg:npm/test",
			Name:     "test",
			Version:  "1.0.0",
			Licenses: []string{"MIT"},
			Hashes:   map[string]string{"SHA256": "abc"},
		}
		after := Component{
			ID:       "pkg:npm/test",
			Name:     "test",
			Version:  "2.0.0",
			Licenses: []string{"Apache-2.0"},
			Hashes:   map[string]string{"SHA256": "def"},
		}

		changes := compareComponents(before, after)

		if len(changes) != 3 {
			t.Errorf("expected 3 changes, got %d: %v", len(changes), changes)
		}
	})

	t.Run("no changes for identical", func(t *testing.T) {
		comp := Component{
			ID:       "pkg:npm/test",
			Name:     "test",
			Version:  "1.0.0",
			Licenses: []string{"MIT"},
		}

		changes := compareComponents(comp, comp)

		if len(changes) != 0 {
			t.Errorf("expected 0 changes, got %d", len(changes))
		}
	})
}
