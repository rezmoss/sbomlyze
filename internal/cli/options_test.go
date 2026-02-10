package cli

import "testing"

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

func TestParseArgs_WebFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"--web", []string{"sbomlyze", "--web"}},
		{"-web", []string{"sbomlyze", "-web"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ParseArgs(tt.args)
			if !opts.WebServer {
				t.Error("expected WebServer=true")
			}
		})
	}
}

func TestParseArgs_PortFlag(t *testing.T) {
	args := []string{"sbomlyze", "-web", "--port", "3000"}
	opts := ParseArgs(args)
	if opts.WebPort != 3000 {
		t.Errorf("expected WebPort=3000, got %d", opts.WebPort)
	}
}

func TestParseArgs_PortInvalid(t *testing.T) {
	args := []string{"sbomlyze", "-web", "--port", "abc"}
	opts := ParseArgs(args)
	if opts.WebPort != 0 {
		t.Errorf("expected WebPort=0 for invalid port, got %d", opts.WebPort)
	}
}

func TestParseArgs_FormatMdAlias(t *testing.T) {
	args := []string{"sbomlyze", "a.json", "b.json", "-f", "md"}
	opts := ParseArgs(args)
	if opts.Format != "md" {
		t.Errorf("expected Format=md, got %s", opts.Format)
	}
}

func TestParseArgs_FlagsIgnored(t *testing.T) {
	args := []string{"sbomlyze", "--unknown", "a.json"}
	opts := ParseArgs(args)
	if len(opts.Files) != 1 || opts.Files[0] != "a.json" {
		t.Errorf("expected 1 file a.json, got %v", opts.Files)
	}
}

func TestDefaultParseOptions(t *testing.T) {
	opts := DefaultParseOptions()
	if opts.Strict {
		t.Error("expected Strict=false")
	}
	if len(opts.Warnings) != 0 {
		t.Errorf("expected empty Warnings, got %v", opts.Warnings)
	}
}

func TestAddWarning(t *testing.T) {
	opts := DefaultParseOptions()
	opts.AddWarning("test.json", "missing field", "name")
	if len(opts.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(opts.Warnings))
	}
	if opts.Warnings[0].File != "test.json" {
		t.Errorf("expected file=test.json, got %s", opts.Warnings[0].File)
	}
	if opts.Warnings[0].Message != "missing field" {
		t.Errorf("expected message='missing field', got %s", opts.Warnings[0].Message)
	}
	if opts.Warnings[0].Field != "name" {
		t.Errorf("expected field=name, got %s", opts.Warnings[0].Field)
	}
}

func TestAddWarning_Multiple(t *testing.T) {
	opts := DefaultParseOptions()
	opts.AddWarning("a.json", "warn1", "")
	opts.AddWarning("b.json", "warn2", "field2")
	if len(opts.Warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d", len(opts.Warnings))
	}
}
