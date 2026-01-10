package cli

import (
	"strings"
)

// ParseWarning represents a non-fatal issue found during parsing
type ParseWarning struct {
	File    string `json:"file"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

// ParseOptions controls parsing behavior
type ParseOptions struct {
	Strict   bool
	Warnings []ParseWarning
}

// Options holds all command line options
type Options struct {
	Files       []string
	JSONOutput  bool
	PolicyFile  string
	Strict      bool
	Format      string // text, json, sarif, junit, markdown, patch
	Interactive bool   // Interactive TUI mode
}

// DefaultParseOptions returns tolerant parsing options
func DefaultParseOptions() ParseOptions {
	return ParseOptions{
		Strict:   false,
		Warnings: []ParseWarning{},
	}
}

// AddWarning adds a warning (in tolerant mode) or could trigger error (in strict mode)
func (p *ParseOptions) AddWarning(file, message, field string) {
	p.Warnings = append(p.Warnings, ParseWarning{
		File:    file,
		Message: message,
		Field:   field,
	})
}

// ParseArgs parses command line arguments into Options
func ParseArgs(args []string) Options {
	opts := Options{
		Strict: false,  // default is tolerant
		Format: "text", // default is text
	}

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
			opts.JSONOutput = true
			opts.Format = "json"
		case "--strict":
			opts.Strict = true
		case "--tolerant":
			opts.Strict = false
		case "--policy":
			if i+1 < len(args) {
				opts.PolicyFile = args[i+1]
				i++
			}
		case "--format", "-f":
			if i+1 < len(args) {
				opts.Format = args[i+1]
				if opts.Format == "json" {
					opts.JSONOutput = true
				}
				i++
			}
		case "--interactive", "-i":
			opts.Interactive = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				opts.Files = append(opts.Files, args[i])
			}
		}
	}

	return opts
}
