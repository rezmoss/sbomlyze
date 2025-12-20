package main

import (
	"strings"
)

// computeComponentID generates a canonical identity for a component
// using the following precedence:
// 1. PURL (normalized - without version/qualifiers)
// 2. CPE (normalized - vendor:product only)
// 3. BOM-ref / SPDXID
// 4. Namespace + Name
// 5. Name only (fallback)
func computeComponentID(c Component) string {
	// 1. PURL - highest precedence
	if c.PURL != "" {
		return normalizePURL(c.PURL)
	}

	// 2. CPE - second precedence
	if len(c.CPEs) > 0 {
		for _, cpe := range c.CPEs {
			normalized := normalizeCPE(cpe)
			if normalized != "" {
				return normalized
			}
		}
	}

	// 3. BOM-ref or SPDXID
	if c.BOMRef != "" {
		return "ref:" + c.BOMRef
	}
	if c.SPDXID != "" {
		return "ref:" + c.SPDXID
	}

	// 4. Namespace + Name
	if c.Namespace != "" {
		return c.Namespace + "/" + c.Name
	}

	// 5. Name only (fallback)
	return c.Name
}

// normalizeCPE extracts vendor:product from a CPE string
// Supports both CPE 2.3 and CPE 2.2 formats
// Returns empty string if CPE is invalid
func normalizeCPE(cpe string) string {
	if cpe == "" {
		return ""
	}

	// CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
	if strings.HasPrefix(cpe, "cpe:2.3:") {
		parts := strings.Split(cpe, ":")
		if len(parts) >= 5 {
			vendor := parts[3]
			product := parts[4]
			if vendor != "" && vendor != "*" && product != "" && product != "*" {
				return "cpe:" + vendor + ":" + product
			}
		}
		return ""
	}

	// CPE 2.2 format: cpe:/part:vendor:product:version...
	if strings.HasPrefix(cpe, "cpe:/") {
		rest := cpe[5:] // remove "cpe:/"
		parts := strings.Split(rest, ":")
		if len(parts) >= 3 {
			vendor := parts[1]
			product := parts[2]
			if vendor != "" && product != "" {
				return "cpe:" + vendor + ":" + product
			}
		}
		return ""
	}

	return ""
}

// assignComponentIDs assigns IDs to all components using the identity matcher
func assignComponentIDs(comps []Component) []Component {
	result := make([]Component, len(comps))
	for i, c := range comps {
		c.ID = computeComponentID(c)
		result[i] = c
	}
	return result
}
