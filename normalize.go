package main

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

// CLIOptions holds all command line options
type CLIOptions struct {
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

// normalizeString trims whitespace and lowercases
func normalizeString(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// normalizeLicense normalizes license identifiers
// - Trims whitespace
// - Preserves case for SPDX identifiers
// - Filters out NOASSERTION and similar
func normalizeLicense(s string) string {
	s = strings.TrimSpace(s)

	// Filter out non-assertions
	lower := strings.ToLower(s)
	if lower == "noassertion" || lower == "none" || lower == "unknown" {
		return ""
	}

	// Uppercase common license IDs for consistency
	if lower == "mit" {
		return "MIT"
	}

	return s
}

// normalizeComponent applies all normalizations to a component
func normalizeComponent(c Component) Component {
	normalized := Component{
		ID:           c.ID,
		Name:         normalizeString(c.Name),
		Version:      strings.TrimSpace(c.Version),
		PURL:         strings.TrimSpace(c.PURL),
		Hashes:       c.Hashes,
		Dependencies: c.Dependencies,
		CPEs:         c.CPEs,
		BOMRef:       strings.TrimSpace(c.BOMRef),
		SPDXID:       strings.TrimSpace(c.SPDXID),
		Namespace:    strings.TrimSpace(c.Namespace),
		Supplier:     strings.TrimSpace(c.Supplier),
		RawJSON:      c.RawJSON, // Preserve original SBOM JSON
	}

	// Normalize and filter licenses
	for _, lic := range c.Licenses {
		normalizedLic := normalizeLicense(lic)
		if normalizedLic != "" {
			normalized.Licenses = append(normalized.Licenses, normalizedLic)
		}
	}

	// Recompute ID if not set (after normalization)
	if normalized.ID == "" {
		normalized.ID = computeComponentID(normalized)
	}

	return normalized
}

// normalizeComponents normalizes a slice of components
func normalizeComponents(comps []Component) []Component {
	result := make([]Component, len(comps))
	for i, c := range comps {
		result[i] = normalizeComponent(c)
	}
	return result
}

// parseArgs parses command line arguments into CLIOptions
func parseArgs(args []string) CLIOptions {
	opts := CLIOptions{
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
