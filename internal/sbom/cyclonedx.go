package sbom

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rezmoss/sbomlyze/internal/identity"
)

// ParseCycloneDX parses CycloneDX JSON.
func ParseCycloneDX(data []byte) ([]Component, error) {
	comps, _, err := ParseCycloneDXWithInfo(data)
	return comps, err
}

// ParseCycloneDXWithInfo parses CycloneDX JSON with metadata.
func ParseCycloneDXWithInfo(data []byte) ([]Component, SBOMInfo, error) {
	var rawDoc struct {
		Components []json.RawMessage `json:"components"`
	}
	_ = json.Unmarshal(data, &rawDoc) // Ignore error, rawDoc.Components may be nil

	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, SBOMInfo{}, err
	}

	return extractCycloneDX(&bom, rawDoc.Components)
}

// ParseCycloneDXXML parses CycloneDX XML.
func ParseCycloneDXXML(data []byte) ([]Component, error) {
	comps, _, err := ParseCycloneDXXMLWithInfo(data)
	return comps, err
}

// ParseCycloneDXXMLWithInfo parses CycloneDX XML with metadata.
// XML components don't have RawJSON (they aren't JSON), so that field stays nil.
func ParseCycloneDXXMLWithInfo(data []byte) ([]Component, SBOMInfo, error) {
	var bom cdx.BOM
	if err := xml.Unmarshal(data, &bom); err != nil {
		return nil, SBOMInfo{}, err
	}
	return extractCycloneDX(&bom, nil)
}

// extractCycloneDX contains the shared component+metadata extraction logic
// used by both the JSON and XML parsers. rawComponents provides per-component
// raw JSON blobs (nil for XML input).
func extractCycloneDX(bom *cdx.BOM, rawComponents []json.RawMessage) ([]Component, SBOMInfo, error) {
	info := extractCycloneDXInfo(bom)
	comps := extractCycloneDXComponents(bom, rawComponents)
	resolveCycloneDXDependencies(bom, comps)
	return comps, info, nil
}

func extractCycloneDXInfo(bom *cdx.BOM) SBOMInfo {
	info := SBOMInfo{Format: "CycloneDX"}
	if v := bom.SpecVersion.String(); !strings.HasPrefix(v, "SpecVersion(") {
		info.SpecVersion = v
	}
	if bom.Metadata == nil {
		return info
	}
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
	// Real author/email/contact info, not just the tool name.
	if bom.Metadata.Authors != nil {
		for _, a := range *bom.Metadata.Authors {
			if a.Name != "" {
				info.SBOMAuthor = a.Name
				break
			}
		}
	}
	if info.SBOMAuthor == "" && bom.Metadata.Supplier != nil && bom.Metadata.Supplier.Name != "" {
		info.SBOMAuthor = bom.Metadata.Supplier.Name
	}
	// ISO-8601 timestamp captured at SBOM compilation time.
	if bom.Metadata.Timestamp != "" {
		info.SBOMTimestamp = bom.Metadata.Timestamp
	}
	// metadata.tools: components list (1.5+) or legacy array
	if bom.Metadata.Tools != nil {
		tools := bom.Metadata.Tools
		switch {
		case tools.Components != nil && len(*tools.Components) > 0:
			info.ToolName = (*tools.Components)[0].Name
			info.ToolVersion = (*tools.Components)[0].Version
		case tools.Tools != nil && len(*tools.Tools) > 0:
			info.ToolName = (*tools.Tools)[0].Name
			info.ToolVersion = (*tools.Tools)[0].Version
		}
	}
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
	return info
}

func extractCycloneDXComponents(bom *cdx.BOM, rawComponents []json.RawMessage) []Component {
	var comps []Component
	if bom.Components == nil {
		return comps
	}
	for i, c := range *bom.Components {
		comp := Component{
			Name:      c.Name,
			Version:   c.Version,
			Hashes:    make(map[string]string),
			BOMRef:    c.BOMRef,
			Namespace: c.Group,
			Type:      string(c.Type),
		}
		if c.PackageURL != "" {
			comp.PURL = c.PackageURL
		}
		if c.CPE != "" {
			comp.CPEs = append(comp.CPEs, c.CPE)
		}
		if c.Licenses != nil {
			for _, lic := range *c.Licenses {
				switch {
				case lic.License != nil && lic.License.ID != "":
					comp.Licenses = append(comp.Licenses, lic.License.ID)
				case lic.License != nil && lic.License.Name != "":
					// declared name, not an SPDX ID
					comp.Licenses = append(comp.Licenses, lic.License.Name)
					comp.NonSPDXLicenses = append(comp.NonSPDXLicenses, lic.License.Name)
				}
				// SPDX expr, e.g. "MIT AND BSD-2-Clause"
				if lic.Expression != "" {
					comp.Licenses = append(comp.Licenses, lic.Expression)
				}
			}
		}
		if c.Hashes != nil {
			for _, h := range *c.Hashes {
				comp.Hashes[string(h.Algorithm)] = h.Value
			}
		}
		// supplier, else provenance fallback (syft uses publisher for maintainer)
		switch {
		case c.Supplier != nil && c.Supplier.Name != "":
			comp.Supplier = c.Supplier.Name
		case c.Publisher != "":
			comp.Supplier = c.Publisher
		case c.Manufacturer != nil && c.Manufacturer.Name != "":
			comp.Supplier = c.Manufacturer.Name
		case c.Authors != nil && len(*c.Authors) > 0 && (*c.Authors)[0].Name != "":
			comp.Supplier = (*c.Authors)[0].Name
		case c.Author != "":
			comp.Supplier = c.Author
		}
		comp.Locations = cycloneDXLocations(c)
		if c.Properties != nil {
			for _, p := range *c.Properties {
				switch {
				case p.Name == "syft:metadata:h1Digest" && p.Value != "":
					comp.Digests = map[string]string{DigestGoH1: p.Value}
				case p.Name == "syft:package:type":
					comp.PkgType = p.Value
				}
			}
		}
		if i < len(rawComponents) {
			comp.RawJSON = rawComponents[i]
		}
		comp.ID = identity.ComputeID(comp.ToIdentity())
		comps = append(comps, comp)
	}
	return comps
}

// syftLocationRe: syft:location:N:path
var syftLocationRe = regexp.MustCompile(`^syft:location:(\d+):path$`)

// cycloneDXLocations: Syft, sbomlyze, evidence locations
func cycloneDXLocations(c cdx.Component) []string {
	type indexed struct {
		n    int
		path string
	}
	var syftLocs []indexed
	var locs []string
	if c.Properties != nil {
		for _, p := range *c.Properties {
			if p.Value == "" {
				continue
			}
			if m := syftLocationRe.FindStringSubmatch(p.Name); m != nil {
				n, _ := strconv.Atoi(m[1])
				syftLocs = append(syftLocs, indexed{n, p.Value})
			} else if p.Name == "sbomlyze:location" {
				locs = append(locs, p.Value)
			}
		}
	}
	sort.SliceStable(syftLocs, func(i, j int) bool { return syftLocs[i].n < syftLocs[j].n })
	seen := make(map[string]bool)
	var out []string
	add := func(path string) {
		if path != "" && !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	for _, l := range syftLocs {
		add(l.path)
	}
	for _, l := range locs {
		add(l)
	}
	if c.Evidence != nil && c.Evidence.Occurrences != nil {
		for _, o := range *c.Evidence.Occurrences {
			add(o.Location)
		}
	}
	return out
}

func resolveCycloneDXDependencies(bom *cdx.BOM, comps []Component) {
	if bom.Dependencies == nil || len(comps) == 0 {
		return
	}
	refToIdx := make(map[string]int, len(comps))
	for i, c := range comps {
		if c.BOMRef != "" {
			refToIdx[c.BOMRef] = i
		}
	}
	for _, d := range *bom.Dependencies {
		parentIdx, ok := refToIdx[d.Ref]
		if !ok {
			continue
		}
		// entry presence = declaration, even w/ empty dependsOn (leaf)
		comps[parentIdx].DepsDeclared = true
		if d.Dependencies == nil {
			continue
		}
		for _, childRef := range *d.Dependencies {
			if childIdx, ok := refToIdx[childRef]; ok {
				comps[parentIdx].Dependencies = append(comps[parentIdx].Dependencies, comps[childIdx].ID)
			}
		}
	}
}
