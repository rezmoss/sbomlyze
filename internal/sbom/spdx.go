package sbom

import (
	"encoding/json"
	"os"

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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rawDoc struct {
		Packages []json.RawMessage `json:"packages"`
	}
	_ = json.Unmarshal(data, &rawDoc) // Ignore error, may not have packages array

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	doc, err := spdxjson.Read(f)
	if err != nil {
		return nil, err
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
	return comps, nil
}
