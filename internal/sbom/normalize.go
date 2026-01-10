package sbom

import (
	"strings"

	"github.com/rezmoss/sbomlyze/internal/identity"
)

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

// NormalizeComponent applies all normalizations to a component
func NormalizeComponent(c Component) Component {
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
		normalized.ID = identity.ComputeID(normalized.ToIdentity())
	}

	return normalized
}

// NormalizeComponents normalizes a slice of components
func NormalizeComponents(comps []Component) []Component {
	result := make([]Component, len(comps))
	for i, c := range comps {
		result[i] = NormalizeComponent(c)
	}
	return result
}
