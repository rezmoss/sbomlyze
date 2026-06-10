package sbom

import (
	"encoding/json"
	"os"

	"strings"
	"github.com/rezmoss/sbomlyze/internal/identity"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
)

// ParseSPDXFromBytes parses SPDX from bytes.
func ParseSPDXFromBytes(data []byte) ([]Component, error) {
	tmpFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()

	if _, err := tmpFile.Write(data); err != nil {
		return nil, err
	}
	_ = tmpFile.Close()

	return ParseSPDX(tmpFile.Name())
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

	var rawDoc struct {
		Packages []json.RawMessage `json:"packages"`
	}
	_ = json.Unmarshal(data, &rawDoc) // Ignore error, may not have packages array

	f, err := os.Open(path)
	if err != nil {
		return nil, SBOMInfo{}, err
	}
	defer func() { _ = f.Close() }()

	doc, err := spdxjson.Read(f)
	if err != nil {
		return nil, SBOMInfo{}, err
	}

	var info SBOMInfo
	// SPDX 2.x puts author/timestamp in creationInfo at the document level.
	if doc.CreationInfo != nil {
		info.SBOMTimestamp = doc.CreationInfo.Created
		for _, creator := range doc.CreationInfo.Creators {
			// Creator is a struct; Creator field is "Tool: name" / "Person: name" etc.
			name := strings.TrimSpace(creator.Creator)
			if name == "" {
				continue
			}
			if _, after, ok := strings.Cut(name, ":"); ok {
				name = strings.TrimSpace(after)
			}
			if name != "" {
				info.SBOMAuthor = name
				break
			}
		}
	}

	var comps []Component
	for i, pkg := range doc.Packages {
		comp := Component{
			Name:    pkg.PackageName,
			Version: pkg.PackageVersion,
			Hashes:  make(map[string]string),
			SPDXID:  string(pkg.PackageSPDXIdentifier),
		}
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == spdx.PackageManagerPURL || ref.RefType == "purl" {
				comp.PURL = ref.Locator
			}
			if ref.RefType == "cpe22Type" || ref.RefType == "cpe23Type" {
				comp.CPEs = append(comp.CPEs, ref.Locator)
			}
		}
		if pkg.PackageLicenseConcluded != "" {
			comp.Licenses = append(comp.Licenses, pkg.PackageLicenseConcluded)
		}
		for _, cs := range pkg.PackageChecksums {
			comp.Hashes[string(cs.Algorithm)] = cs.Value
		}
		if i < len(rawDoc.Packages) {
			comp.RawJSON = rawDoc.Packages[i]
		}
		comp.ID = identity.ComputeID(comp.ToIdentity())
		comps = append(comps, comp)
	}
	return comps, info, nil
}
