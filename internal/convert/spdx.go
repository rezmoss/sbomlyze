package convert

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/spdx/tools-golang/spdx/v2/common"
	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	spdxjson "github.com/spdx/tools-golang/json"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

var spdxIDRegexp = regexp.MustCompile(`[^a-zA-Z0-9.-]`)

// SPDX 2.3 JSON output
func WriteSPDX(w io.Writer, comps []sbom.Component, info sbom.SBOMInfo) error {
	doc := &spdxv23.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      spdxDocumentName(info),
		DocumentNamespace: "https://sbomlyze.dev/spdx/" + generateUUID(),
		CreationInfo: &spdxv23.CreationInfo{
			Created: time.Now().UTC().Format(time.RFC3339),
			Creators: []common.Creator{
				{CreatorType: "Tool", Creator: "sbomlyze-convert"},
			},
		},
	}

	var rels []*spdxv23.Relationship
	idToSPDXID := make(map[string]string, len(comps))
	for i, c := range comps {
		pkg := componentToSPDXPackage(c, i)
		doc.Packages = append(doc.Packages, pkg)
		idToSPDXID[c.ID] = string(pkg.PackageSPDXIdentifier)

		rels = append(rels, &spdxv23.Relationship{
			RefA:         common.MakeDocElementID("", "DOCUMENT"),
			RefB:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
			Relationship: common.TypeRelationshipDescribe,
		})
	}

	for i, c := range comps {
		for _, depID := range c.Dependencies {
			if depSPDXID, ok := idToSPDXID[depID]; ok {
				rels = append(rels, &spdxv23.Relationship{
					RefA:         common.MakeDocElementID("", string(doc.Packages[i].PackageSPDXIdentifier)),
					RefB:         common.MakeDocElementID("", depSPDXID),
					Relationship: common.TypeRelationshipDependsOn,
				})
			}
		}
	}

	doc.Relationships = rels

	return spdxjson.Write(doc, w, spdxjson.Indent("  "))
}

func componentToSPDXPackage(c sbom.Component, index int) *spdxv23.Package {
	pkg := &spdxv23.Package{
		PackageName:             c.Name,
		PackageSPDXIdentifier:   spdxIDFor(c, index),
		PackageVersion:          c.Version,
		PackageDownloadLocation: "NOASSERTION",
		FilesAnalyzed:           false,
		PackageCopyrightText:    "NOASSERTION",
	}

	if c.Supplier != "" {
		pkg.PackageSupplier = &common.Supplier{
			Supplier:     c.Supplier,
			SupplierType: "Organization",
		}
	}

	if len(c.Licenses) > 0 {
		pkg.PackageLicenseConcluded = strings.Join(c.Licenses, " AND ")
	} else {
		pkg.PackageLicenseConcluded = "NOASSERTION"
	}

	for algo, val := range c.Hashes {
		pkg.PackageChecksums = append(pkg.PackageChecksums, common.Checksum{
			Algorithm: mapHashAlgorithmToSPDX(algo),
			Value:     val,
		})
	}

	var refs []*spdxv23.PackageExternalReference

	if c.PURL != "" {
		refs = append(refs, &spdxv23.PackageExternalReference{
			Category: common.CategoryPackageManager,
			RefType:  common.TypePackageManagerPURL,
			Locator:  c.PURL,
		})
	}

	for _, cpe := range c.CPEs {
		refs = append(refs, &spdxv23.PackageExternalReference{
			Category: common.CategorySecurity,
			RefType:  common.TypeSecurityCPE23Type,
			Locator:  cpe,
		})
	}

	if len(refs) > 0 {
		pkg.PackageExternalReferences = refs
	}

	return pkg
}

func spdxIDFor(c sbom.Component, index int) common.ElementID {
	if c.SPDXID != "" {
		// strip SPDXRef- prefix
		id := strings.TrimPrefix(c.SPDXID, "SPDXRef-")
		return common.ElementID(sanitizeSPDXID(id))
	}
	if c.Name != "" {
		id := sanitizeSPDXID(c.Name)
		if c.Version != "" {
			id += "-" + sanitizeSPDXID(c.Version)
		}
		return common.ElementID(id)
	}
	return common.ElementID(sanitizeSPDXID(fmt.Sprintf("Package-%d", index)))
}

func sanitizeSPDXID(s string) string {
	return spdxIDRegexp.ReplaceAllString(s, "-")
}

// normalize hash algo -> SPDX fmt
func mapHashAlgorithmToSPDX(algo string) common.ChecksumAlgorithm {
	upper := strings.ToUpper(algo)
	switch upper {
	case "SHA256", "SHA-256":
		return common.SHA256
	case "SHA512", "SHA-512":
		return common.SHA512
	case "SHA1", "SHA-1":
		return common.SHA1
	case "SHA384", "SHA-384":
		return common.SHA384
	case "SHA224", "SHA-224":
		return common.SHA224
	case "MD5":
		return common.MD5
	default:
		return common.ChecksumAlgorithm(upper)
	}
}

func spdxDocumentName(info sbom.SBOMInfo) string {
	if info.SourceName != "" {
		return info.SourceName
	}
	return "sbomlyze-converted"
}
