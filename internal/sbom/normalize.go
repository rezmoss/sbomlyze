package sbom

import (
	"strings"

	"github.com/rezmoss/sbomlyze/internal/identity"
)

// normalizeString trims whitespace. Declared case is kept: Go module paths and
// file paths are case-sensitive. Case folding happens only in match keys.
func normalizeString(s string) string {
	return strings.TrimSpace(s)
}

func normalizeLicense(s string) string {
	s = strings.TrimSpace(s)

	lower := strings.ToLower(s)
	if lower == "noassertion" || lower == "none" || lower == "unknown" {
		return ""
	}

	if lower == "mit" {
		return "MIT"
	}

	return s
}

// NormalizeComponent normalizes a component.
func NormalizeComponent(c Component) Component {
	normalized := Component{
		ID:           c.ID,
		Name:         normalizeString(c.Name),
		Version:      strings.TrimSpace(c.Version),
		PURL:         strings.TrimSpace(c.PURL),
		Hashes:       c.Hashes,
		Digests:      c.Digests,
		Dependencies: c.Dependencies,
		DepsDeclared: c.DepsDeclared,
		CPEs:         c.CPEs,
		BOMRef:       strings.TrimSpace(c.BOMRef),
		SPDXID:       strings.TrimSpace(c.SPDXID),
		Namespace:    strings.TrimSpace(c.Namespace),
		Supplier:     strings.TrimSpace(c.Supplier),
		Language:     c.Language,
		FoundBy:      c.FoundBy,
		Type:         c.Type,
		Locations:    c.Locations,
		RawJSON:      c.RawJSON,

		PrimaryLocations: c.PrimaryLocations,
	}

	nonSPDX := make(map[string]bool, len(c.NonSPDXLicenses))
	for _, lic := range c.NonSPDXLicenses {
		nonSPDX[lic] = true
	}

	for _, lic := range c.Licenses {
		normalizedLic := normalizeLicense(lic)
		if normalizedLic != "" {
			normalized.Licenses = append(normalized.Licenses, normalizedLic)
			if nonSPDX[lic] {
				normalized.NonSPDXLicenses = append(normalized.NonSPDXLicenses, normalizedLic)
			}
		}
	}

	if normalized.ID == "" {
		normalized.ID = identity.ComputeID(normalized.ToIdentity())
	}

	return normalized
}

// NormalizeComponents normalizes all components.
func NormalizeComponents(comps []Component) []Component {
	result := make([]Component, len(comps))
	for i, c := range comps {
		result[i] = NormalizeComponent(c)
	}
	return result
}
