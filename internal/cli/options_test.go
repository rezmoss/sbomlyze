package cli

import "testing"

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

func TestParseArgs(t *testing.T) {
	t.Run("parses strict flag", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "--strict"}
		opts := ParseArgs(args)

		if !opts.Strict {
			t.Error("expected Strict=true from --strict flag")
		}
	})

	t.Run("parses tolerant flag", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "--tolerant"}
		opts := ParseArgs(args)

		if opts.Strict {
			t.Error("expected Strict=false from --tolerant flag")
		}
	})

	t.Run("default is tolerant", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json"}
		opts := ParseArgs(args)

		if opts.Strict {
			t.Error("expected default Strict=false")
		}
	})

	t.Run("parses json flag", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "--json"}
		opts := ParseArgs(args)

		if !opts.JSONOutput {
			t.Error("expected JSONOutput=true from --json flag")
		}
		if opts.Format != "json" {
			t.Errorf("expected Format=json, got %s", opts.Format)
		}
	})

	t.Run("parses format flag", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "b.json", "--format", "sarif"}
		opts := ParseArgs(args)

		if opts.Format != "sarif" {
			t.Errorf("expected Format=sarif, got %s", opts.Format)
		}
	})

	t.Run("parses policy flag", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "b.json", "--policy", "policy.json"}
		opts := ParseArgs(args)

		if opts.PolicyFile != "policy.json" {
			t.Errorf("expected PolicyFile=policy.json, got %s", opts.PolicyFile)
		}
	})

	t.Run("parses interactive flag", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "-i"}
		opts := ParseArgs(args)

		if !opts.Interactive {
			t.Error("expected Interactive=true from -i flag")
		}
	})

	t.Run("collects files", func(t *testing.T) {
		args := []string{"sbomlyze", "a.json", "b.json"}
		opts := ParseArgs(args)

		if len(opts.Files) != 2 {
			t.Errorf("expected 2 files, got %d", len(opts.Files))
		}
		if opts.Files[0] != "a.json" || opts.Files[1] != "b.json" {
			t.Errorf("unexpected files: %v", opts.Files)
		}
	})
}
