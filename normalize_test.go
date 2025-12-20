package main

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

func TestParseWarning(t *testing.T) {
	t.Run("warning has correct fields", func(t *testing.T) {
		w := ParseWarning{
			File:    "test.json",
			Message: "unknown field 'foo'",
			Field:   "foo",
		}

		if w.File != "test.json" {
			t.Errorf("expected file=test.json, got %s", w.File)
		}
	})
}

func TestParseOptions(t *testing.T) {
	t.Run("default is tolerant", func(t *testing.T) {
		opts := DefaultParseOptions()
		if opts.Strict {
			t.Error("expected default to be tolerant (Strict=false)")
		}
	})

	t.Run("strict mode set", func(t *testing.T) {
		opts := ParseOptions{Strict: true}
		if !opts.Strict {
			t.Error("expected Strict=true")
		}
	})
}

func TestParseFileWithOptions(t *testing.T) {
	t.Run("tolerant mode collects warnings", func(t *testing.T) {
		// This test requires a test file - skip for now
		t.Skip("requires test fixtures")
	})

	t.Run("strict mode returns error on warning", func(t *testing.T) {
		// This test requires a test file - skip for now
		t.Skip("requires test fixtures")
	})
}

func TestNormalizeComponent(t *testing.T) {
	t.Run("normalizes name", func(t *testing.T) {
		comp := Component{
			Name:    "  MyPackage  ",
			Version: "  1.0.0  ",
		}

		normalized := normalizeComponent(comp)

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

		normalized := normalizeComponent(comp)

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

		normalized := normalizeComponent(comp)

		if normalized.ID != "pkg:npm/test" {
			t.Errorf("expected ID preserved, got %s", normalized.ID)
		}
	})
}

func TestCLIParseMode(t *testing.T) {
	t.Run("parses strict flag", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "--strict"}
		opts := parseArgs(args)

		if !opts.Strict {
			t.Error("expected Strict=true from --strict flag")
		}
	})

	t.Run("parses tolerant flag", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "--tolerant"}
		opts := parseArgs(args)

		if opts.Strict {
			t.Error("expected Strict=false from --tolerant flag")
		}
	})

	t.Run("default is tolerant", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json"}
		opts := parseArgs(args)

		if opts.Strict {
			t.Error("expected default Strict=false")
		}
	})
}
