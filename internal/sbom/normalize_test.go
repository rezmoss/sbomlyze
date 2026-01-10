package sbom

import "testing"

func TestNormalizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"trims whitespace", "  hello  ", "hello"},
		{"lowercases", "HELLO", "hello"},
		{"trims and lowercases", "  HELLO WORLD  ", "hello world"},
		{"empty string", "", ""},
		{"already normalized", "hello", "hello"},
		{"tabs and newlines", "\t\nhello\t\n", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeString(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeLicense(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"uppercase", "MIT", "MIT"},
		{"lowercase becomes upper", "mit", "MIT"},
		{"trims whitespace", "  Apache-2.0  ", "Apache-2.0"},
		{"NOASSERTION normalized", "NOASSERTION", ""},
		{"noassertion normalized", "noassertion", ""},
		{"empty string", "", ""},
		{"complex license", "GPL-2.0-or-later", "GPL-2.0-or-later"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeLicense(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeLicense(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeComponent(t *testing.T) {
	t.Run("normalizes name", func(t *testing.T) {
		comp := Component{
			Name:    "  MyPackage  ",
			Version: "  1.0.0  ",
		}

		normalized := NormalizeComponent(comp)

		if normalized.Name != "mypackage" {
			t.Errorf("expected name=mypackage, got %s", normalized.Name)
		}
		if normalized.Version != "1.0.0" {
			t.Errorf("expected version=1.0.0, got %s", normalized.Version)
		}
	})

	t.Run("normalizes licenses", func(t *testing.T) {
		comp := Component{
			Name:     "test",
			Licenses: []string{"  mit  ", "NOASSERTION", "Apache-2.0"},
		}

		normalized := NormalizeComponent(comp)

		// NOASSERTION should be filtered out
		if len(normalized.Licenses) != 2 {
			t.Errorf("expected 2 licenses, got %d: %v", len(normalized.Licenses), normalized.Licenses)
		}
	})

	t.Run("preserves ID if set", func(t *testing.T) {
		comp := Component{
			ID:   "pkg:npm/test",
			Name: "test",
		}

		normalized := NormalizeComponent(comp)

		if normalized.ID != "pkg:npm/test" {
			t.Errorf("expected ID preserved, got %s", normalized.ID)
		}
	})
}
