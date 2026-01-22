package sbom

import (
	"encoding/json"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rezmoss/sbomlyze/internal/identity"
)

// ParseCycloneDX parses CycloneDX format SBOM data
func ParseCycloneDX(data []byte) ([]Component, error) {
	comps, _, err := ParseCycloneDXWithInfo(data)
	return comps, err
}

// ParseCycloneDXWithInfo parses CycloneDX format SBOM data and extracts metadata
func ParseCycloneDXWithInfo(data []byte) ([]Component, SBOMInfo, error) {
	// First, get raw components to preserve original JSON
	var rawDoc struct {
		Components []json.RawMessage `json:"components"`
	}
	_ = json.Unmarshal(data, &rawDoc) // Ignore error, rawDoc.Components may be nil

	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, SBOMInfo{}, err
	}

	// Extract SBOM info from metadata
	info := SBOMInfo{}
	if bom.Metadata != nil {
		// Check for main component (the subject of the SBOM)
		if bom.Metadata.Component != nil {
			mc := bom.Metadata.Component
			switch mc.Type {
			case cdx.ComponentTypeOS, cdx.ComponentTypeContainer:
				info.OSName = mc.Name
				info.OSVersion = mc.Version
				info.SourceType = string(mc.Type)
			case cdx.ComponentTypeApplication, cdx.ComponentTypeFile:
				info.SourceName = mc.Name
				info.SourceType = string(mc.Type)
			}
		}
		// Check properties for OS info
		if bom.Metadata.Properties != nil {
			for _, prop := range *bom.Metadata.Properties {
				switch strings.ToLower(prop.Name) {
				case "syft:distro:name", "distro:name", "os:name":
					if info.OSName == "" {
						info.OSName = prop.Value
					}
				case "syft:distro:version", "distro:version", "os:version":
					if info.OSVersion == "" {
						info.OSVersion = prop.Value
					}
				case "syft:image:tag", "image:tag":
					if info.SourceName == "" {
						info.SourceName = prop.Value
					}
				}
			}
		}
	}

	var comps []Component
	if bom.Components == nil {
		return comps, info, nil
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
	return comps, info, nil
}
