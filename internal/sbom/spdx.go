package sbom

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/identity"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
)

// ParseSPDXFromBytes parses SPDX from bytes.
func ParseSPDXFromBytes(data []byte) ([]Component, error) {
	comps, _, err := parseSPDXData(data)
	return comps, err
}

// ParseSPDX parses an SPDX file.
func ParseSPDX(path string) ([]Component, error) {
	comps, _, err := ParseSPDXWithInfo(path)
	return comps, err
}

// ParseSPDXWithInfo parses an SPDX file and extracts SBOM-level metadata
// (author from creationInfo.creators, timestamp from creationInfo.created).
func ParseSPDXWithInfo(path string) ([]Component, SBOMInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, SBOMInfo{}, err
	}
	return parseSPDXData(data)
}

// spdxLicenseValue: licence string, or "" if NONE/NOASSERTION/blank
func spdxLicenseValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "NONE" || s == "NOASSERTION" {
		return ""
	}
	return s
}

// splitToolNameVersion splits "name-version" (e.g. "syft-1.40.1"); version must start w/ digit.
func splitToolNameVersion(s string) (string, string) {
	if i := strings.LastIndex(s, "-"); i > 0 && i < len(s)-1 {
		if v := s[i+1:]; v[0] >= '0' && v[0] <= '9' {
			return s[:i], v
		}
	}
	return s, ""
}

func parseSPDXData(data []byte) ([]Component, SBOMInfo, error) {
	var rawDoc struct {
		Packages []json.RawMessage `json:"packages"`
	}
	_ = json.Unmarshal(data, &rawDoc) // may not have packages array

	doc, err := spdxjson.Read(bytes.NewReader(data))
	if err != nil {
		return nil, SBOMInfo{}, err
	}

	info := SBOMInfo{Format: "SPDX", SpecVersion: doc.SPDXVersion}
	// creationInfo: Tool -> tool meta, Person/Org -> author
	if doc.CreationInfo != nil {
		info.SBOMTimestamp = doc.CreationInfo.Created
		for _, creator := range doc.CreationInfo.Creators {
			name := strings.TrimSpace(creator.Creator)
			if name == "" {
				continue
			}
			switch creator.CreatorType {
			case "Tool":
				if info.ToolName == "" {
					info.ToolName, info.ToolVersion = splitToolNameVersion(name)
				}
			default:
				if info.SBOMAuthor == "" {
					info.SBOMAuthor = name
				}
			}
		}
	}

	var comps []Component
	for i, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		comp := Component{
			Name:    pkg.PackageName,
			Version: pkg.PackageVersion,
			Hashes:  make(map[string]string),
			SPDXID:  string(pkg.PackageSPDXIdentifier),
		}
		for _, ref := range pkg.PackageExternalReferences {
			if ref == nil {
				continue
			}
			if ref.RefType == spdx.PackageManagerPURL || ref.RefType == "purl" {
				comp.PURL = ref.Locator
			}
			if ref.RefType == "cpe22Type" || ref.RefType == "cpe23Type" {
				comp.CPEs = append(comp.CPEs, ref.Locator)
			}
		}
		// concluded if meaningful, else declared; NONE/NOASSERTION = absent
		if lic := spdxLicenseValue(pkg.PackageLicenseConcluded); lic != "" {
			comp.Licenses = append(comp.Licenses, lic)
		} else if lic := spdxLicenseValue(pkg.PackageLicenseDeclared); lic != "" {
			comp.Licenses = append(comp.Licenses, lic)
		}
		for _, cs := range pkg.PackageChecksums {
			comp.Hashes[string(cs.Algorithm)] = cs.Value
		}
		// supplier first, originator fallback; NOASSERTION = absent
		if s := pkg.PackageSupplier; s != nil && s.Supplier != "" && s.Supplier != "NOASSERTION" {
			comp.Supplier = s.Supplier
		}
		if o := pkg.PackageOriginator; comp.Supplier == "" && o != nil && o.Originator != "" && o.Originator != "NOASSERTION" {
			comp.Supplier = o.Originator
		}
		if locs := spdxSourceInfoPaths(pkg.PackageSourceInfo); len(locs) > 0 {
			comp.Locations, comp.PrimaryLocations = locs, locs[:1:1]
		}
		if i < len(rawDoc.Packages) {
			comp.RawJSON = rawDoc.Packages[i]
		}
		comp.ID = identity.ComputeID(comp.ToIdentity())
		comps = append(comps, comp)
	}

	// file inventory
	fileByID := make(map[string]string, len(doc.Files))
	for _, f := range doc.Files {
		if f == nil {
			continue
		}
		path := NormalizeFilePath(f.FileName)
		if path == "" {
			continue
		}
		e := FileEntry{Path: path}
		for _, cs := range f.Checksums {
			// syft writes all-zero SHA1 for unhashed files
			if cs.Value != "" && strings.Trim(cs.Value, "0") != "" {
				if e.Hashes == nil {
					e.Hashes = make(map[string]string, len(f.Checksums))
				}
				e.Hashes[string(cs.Algorithm)] = cs.Value
			}
		}
		info.Files = append(info.Files, e)
		fileByID[string(f.FileSPDXIdentifier)] = path
	}

	// relationships -> dep edges. DEPENDS_ON: A dep B; DEPENDENCY_OF: A is dep of B
	idToIdx := make(map[string]int, len(comps))
	for i, c := range comps {
		idToIdx[c.SPDXID] = i
	}
	// described root contains all files; not ownership
	described := make(map[string]bool)
	for _, rel := range doc.Relationships {
		if rel != nil && rel.Relationship == "DESCRIBES" {
			described[string(rel.RefB.ElementRefID)] = true
		}
	}
	for _, rel := range doc.Relationships {
		if rel == nil {
			continue
		}
		// CONTAINS = ownership; CONTAINED_BY reversed
		if rel.Relationship == "CONTAINS" || rel.Relationship == "CONTAINED_BY" {
			pkgRef, fileRef := string(rel.RefA.ElementRefID), string(rel.RefB.ElementRefID)
			if rel.Relationship == "CONTAINED_BY" {
				pkgRef, fileRef = fileRef, pkgRef
			}
			if idx, ok := idToIdx[pkgRef]; ok && !described[pkgRef] {
				if path, ok := fileByID[fileRef]; ok {
					comps[idx].OwnedFiles = append(comps[idx].OwnedFiles, path)
				}
			}
			continue
		}
		var parentRef, childRef string
		switch rel.Relationship {
		case "DEPENDS_ON":
			// NONE = declared leaf; NOASSERTION = unknown (not declared)
			if rel.RefB.SpecialID == "NONE" {
				if idx, ok := idToIdx[string(rel.RefA.ElementRefID)]; ok {
					comps[idx].DepsDeclared = true
				}
				continue
			}
			if rel.RefB.SpecialID == "NOASSERTION" {
				continue
			}
			parentRef, childRef = string(rel.RefA.ElementRefID), string(rel.RefB.ElementRefID)
		case "DEPENDENCY_OF":
			parentRef, childRef = string(rel.RefB.ElementRefID), string(rel.RefA.ElementRefID)
		default:
			continue
		}
		parentIdx, pok := idToIdx[parentRef]
		childIdx, cok := idToIdx[childRef]
		if pok && cok {
			comps[parentIdx].Dependencies = append(comps[parentIdx].Dependencies, comps[childIdx].ID)
		}
	}
	// scanned image/dir root is the source, not a package
	comps = slices.DeleteFunc(comps, func(c Component) bool {
		typ := spdxRootType(c)
		if !described[c.SPDXID] || typ == "" {
			return false
		}
		if info.SourceName == "" {
			info.SourceName, info.SourceType, info.SourceVersion = c.Name, typ, c.Version
		}
		return true
	})
	return comps, info, nil
}

// spdxRootType: source type of a scan root package, else ""
func spdxRootType(c Component) string {
	// tools-golang strips the SPDXRef- prefix
	if rest, ok := strings.CutPrefix(strings.TrimPrefix(c.SPDXID, "SPDXRef-"), "DocumentRoot-"); ok {
		typ, _, _ := strings.Cut(rest, "-")
		return strings.ToLower(typ)
	}
	if strings.HasPrefix(c.PURL, "pkg:oci/") || strings.HasPrefix(c.PURL, "pkg:docker/") {
		return "image"
	}
	return ""
}

// spdxSourceInfoPaths: syft "acquired package info from X: /a, /b"
func spdxSourceInfoPaths(si string) []string {
	rest, ok := strings.CutPrefix(si, "acquired package info from ")
	if !ok {
		return nil
	}
	_, paths, ok := strings.Cut(rest, ": ")
	if !ok {
		return nil
	}
	var out []string
	for _, p := range strings.Split(paths, ", ") {
		if p = strings.TrimSpace(p); strings.HasPrefix(p, "/") {
			out = append(out, p)
		}
	}
	return out
}
