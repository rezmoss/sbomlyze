package convert

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// CDX 1.5 JSON output
func WriteCycloneDX(w io.Writer, comps []sbom.Component, info sbom.SBOMInfo) error {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_5
	bom.SerialNumber = generateURNUUID()
	bom.Metadata = buildCDXMetadata(info)

	cdxComps := make([]cdx.Component, 0, len(comps))
	for _, c := range comps {
		cdxComps = append(cdxComps, componentToCDX(c))
	}
	bom.Components = &cdxComps
	bom.Dependencies = buildCDXDependencies(comps)

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

func componentToCDX(c sbom.Component) cdx.Component {
	comp := cdx.Component{
		Type:       mapComponentType(c.Type),
		Name:       c.Name,
		Version:    c.Version,
		PackageURL: c.PURL,
		BOMRef:     bomRefOrGenerate(c),
		Group:      c.Namespace,
	}

	if c.Supplier != "" {
		comp.Supplier = &cdx.OrganizationalEntity{Name: c.Supplier}
	}

	if len(c.CPEs) > 0 {
		comp.CPE = c.CPEs[0]
	}

	if len(c.Licenses) > 0 {
		licenses := make(cdx.Licenses, 0, len(c.Licenses))
		for _, lic := range c.Licenses {
			licenses = append(licenses, cdx.LicenseChoice{
				License: &cdx.License{ID: lic},
			})
		}
		comp.Licenses = &licenses
	}

	if len(c.Hashes) > 0 {
		hashes := make([]cdx.Hash, 0, len(c.Hashes))
		for algo, val := range c.Hashes {
			hashes = append(hashes, cdx.Hash{
				Algorithm: mapHashAlgorithmToCDX(algo),
				Value:     val,
			})
		}
		comp.Hashes = &hashes
	}

	var props []cdx.Property

	for i := 1; i < len(c.CPEs); i++ {
		props = append(props, cdx.Property{
			Name:  "sbomlyze:cpe",
			Value: c.CPEs[i],
		})
	}

	if c.SPDXID != "" {
		props = append(props, cdx.Property{
			Name:  "sbomlyze:spdxid",
			Value: c.SPDXID,
		})
	}

	if c.Language != "" {
		props = append(props, cdx.Property{
			Name:  "sbomlyze:language",
			Value: c.Language,
		})
	}
	if c.FoundBy != "" {
		props = append(props, cdx.Property{
			Name:  "sbomlyze:foundBy",
			Value: c.FoundBy,
		})
	}
	for _, loc := range c.Locations {
		props = append(props, cdx.Property{
			Name:  "sbomlyze:location",
			Value: loc,
		})
	}

	if len(props) > 0 {
		comp.Properties = &props
	}

	return comp
}

func buildCDXMetadata(info sbom.SBOMInfo) *cdx.Metadata {
	meta := &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "sbomlyze",
					Version: "convert",
				},
			},
		},
	}

	var props []cdx.Property
	if info.OSName != "" {
		props = append(props, cdx.Property{Name: "sbomlyze:os:name", Value: info.OSName})
	}
	if info.OSVersion != "" {
		props = append(props, cdx.Property{Name: "sbomlyze:os:version", Value: info.OSVersion})
	}
	if info.SourceType != "" {
		props = append(props, cdx.Property{Name: "sbomlyze:source:type", Value: info.SourceType})
	}
	if info.SourceName != "" {
		props = append(props, cdx.Property{Name: "sbomlyze:source:name", Value: info.SourceName})
	}
	if len(props) > 0 {
		meta.Properties = &props
	}

	return meta
}

func buildCDXDependencies(comps []sbom.Component) *[]cdx.Dependency {
	idToRef := make(map[string]string, len(comps))
	for _, c := range comps {
		idToRef[c.ID] = bomRefOrGenerate(c)
	}

	deps := make([]cdx.Dependency, 0, len(comps))
	for _, c := range comps {
		dep := cdx.Dependency{Ref: idToRef[c.ID]}

		if len(c.Dependencies) > 0 {
			dependsOn := make([]string, 0, len(c.Dependencies))
			for _, depID := range c.Dependencies {
				if depRef, ok := idToRef[depID]; ok {
					dependsOn = append(dependsOn, depRef)
				}
			}
			if len(dependsOn) > 0 {
				dep.Dependencies = &dependsOn
			}
		}

		deps = append(deps, dep)
	}

	if len(deps) == 0 {
		return nil
	}
	return &deps
}

// normalize hash algo name -> CDX fmt
func mapHashAlgorithmToCDX(algo string) cdx.HashAlgorithm {
	upper := strings.ToUpper(algo)
	switch upper {
	case "SHA256", "SHA-256":
		return cdx.HashAlgoSHA256
	case "SHA512", "SHA-512":
		return cdx.HashAlgoSHA512
	case "SHA1", "SHA-1":
		return cdx.HashAlgoSHA1
	case "SHA384", "SHA-384":
		return cdx.HashAlgoSHA384
	case "MD5":
		return cdx.HashAlgoMD5
	default:
		return cdx.HashAlgorithm(upper)
	}
}

func mapComponentType(t string) cdx.ComponentType {
	switch strings.ToLower(t) {
	case "application":
		return cdx.ComponentTypeApplication
	case "framework":
		return cdx.ComponentTypeFramework
	case "library", "":
		return cdx.ComponentTypeLibrary
	case "container":
		return cdx.ComponentTypeContainer
	case "operating-system":
		return cdx.ComponentTypeOS
	case "device":
		return cdx.ComponentTypeDevice
	case "firmware":
		return cdx.ComponentTypeFirmware
	case "file":
		return cdx.ComponentTypeFile
	default:
		return cdx.ComponentTypeLibrary
	}
}

// BOMRef fallback: PURL > name@ver > name > ID
func bomRefOrGenerate(c sbom.Component) string {
	if c.BOMRef != "" {
		return c.BOMRef
	}
	if c.PURL != "" {
		return c.PURL
	}
	if c.Name != "" {
		if c.Version != "" {
			return c.Name + "@" + c.Version
		}
		return c.Name
	}
	return c.ID
}

func generateURNUUID() string {
	return "urn:uuid:" + generateUUID()
}

func generateUUID() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
