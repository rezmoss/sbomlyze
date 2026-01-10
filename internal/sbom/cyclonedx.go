package sbom

import (
	"encoding/json"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rezmoss/sbomlyze/internal/identity"
)

// ParseCycloneDX parses CycloneDX format SBOM data
func ParseCycloneDX(data []byte) ([]Component, error) {
	// First, get raw components to preserve original JSON
	var rawDoc struct {
		Components []json.RawMessage `json:"components"`
	}
	_ = json.Unmarshal(data, &rawDoc) // Ignore error, rawDoc.Components may be nil

	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	var comps []Component
	if bom.Components == nil {
		return comps, nil
	}

	for i, c := range *bom.Components {
		comp := Component{
			Name:      c.Name,
			Version:   c.Version,
			Hashes:    make(map[string]string),
			BOMRef:    c.BOMRef,
			Namespace: c.Group,
		}
		if c.PackageURL != "" {
			comp.PURL = c.PackageURL
		}
		if c.CPE != "" {
			comp.CPEs = append(comp.CPEs, c.CPE)
		}
		if c.Licenses != nil {
			for _, lic := range *c.Licenses {
				if lic.License != nil && lic.License.ID != "" {
					comp.Licenses = append(comp.Licenses, lic.License.ID)
				}
			}
		}
		if c.Hashes != nil {
			for _, h := range *c.Hashes {
				comp.Hashes[string(h.Algorithm)] = h.Value
			}
		}
		// Extract supplier info
		if c.Supplier != nil && c.Supplier.Name != "" {
			comp.Supplier = c.Supplier.Name
		}
		// Preserve raw JSON if available
		if i < len(rawDoc.Components) {
			comp.RawJSON = rawDoc.Components[i]
		}
		// Compute ID using identity matcher
		comp.ID = identity.ComputeID(comp.ToIdentity())
		comps = append(comps, comp)
	}
	return comps, nil
}
