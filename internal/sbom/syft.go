package sbom

import (
	"encoding/json"

	"github.com/rezmoss/sbomlyze/internal/identity"
)

// ParseSyft parses Syft format SBOM data
func ParseSyft(data []byte) ([]Component, error) {
	comps, _, err := ParseSyftWithInfo(data)
	return comps, err
}

// ParseSyftWithInfo parses Syft format SBOM data and extracts source/distro info
func ParseSyftWithInfo(data []byte) ([]Component, SBOMInfo, error) {
	// Parse document structure - use RawMessage for optional fields to prevent parse failures
	var doc struct {
		Artifacts             []json.RawMessage `json:"artifacts"`
		ArtifactRelationships []struct {
			Parent string `json:"parent"`
			Child  string `json:"child"`
			Type   string `json:"type"`
		} `json:"artifactRelationships"`
		Source json.RawMessage `json:"source"` // RawMessage to handle missing/malformed
		Distro json.RawMessage `json:"distro"` // RawMessage to handle object or array
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, SBOMInfo{}, err
	}

	var info SBOMInfo

	// Parse source flexibly - ignore errors, just use empty values
	if len(doc.Source) > 0 {
		var sourceInfo struct {
			Type   string `json:"type"`
			Target struct {
				UserInput string `json:"userInput"`
			} `json:"target"`
		}
		if err := json.Unmarshal(doc.Source, &sourceInfo); err == nil {
			info.SourceType = sourceInfo.Type
			info.SourceName = sourceInfo.Target.UserInput
		}
		// If parsing fails, continue with empty source info
	}

	// Parse distro flexibly - can be object or array, ignore errors
	if len(doc.Distro) > 0 {
		var distroInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			ID      string `json:"id"`
		}
		// Try parsing as object first
		if err := json.Unmarshal(doc.Distro, &distroInfo); err != nil {
			// Try parsing as array and take first element
			var distroArray []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				ID      string `json:"id"`
			}
			if err := json.Unmarshal(doc.Distro, &distroArray); err == nil && len(distroArray) > 0 {
				distroInfo = distroArray[0]
			}
			// If both fail, continue with empty distro info
		}
		info.OSName = distroInfo.Name
		info.OSVersion = distroInfo.Version
		// If distro name is empty but ID is set, use ID
		if info.OSName == "" && distroInfo.ID != "" {
			info.OSName = distroInfo.ID
		}
	}

	// Build Syft artifact ID → component index map for relationship resolution
	syftIDToIdx := make(map[string]int)

	var comps []Component
	for _, rawArtifact := range doc.Artifacts {
		// Parse the artifact for our normalized fields
		var a struct {
			SyftID   string `json:"id"`
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Type     string `json:"type"`
			Language string `json:"language"`
			FoundBy  string `json:"foundBy"`
			Licenses []struct {
				Value          string `json:"value"`
				SPDXExpression string `json:"spdxExpression"`
			} `json:"licenses"`
			CPEs []struct {
				CPE string `json:"cpe"`
			} `json:"cpes"`
		}
		if err := json.Unmarshal(rawArtifact, &a); err != nil {
			continue // Skip malformed artifacts
		}

		comp := Component{
			Name:     a.Name,
			Version:  a.Version,
			PURL:     a.PURL,
			Type:     a.Type,
			Language: a.Language,
			FoundBy:  a.FoundBy,
			Hashes:   make(map[string]string),
			RawJSON:  rawArtifact, // Preserve the original JSON
		}
		for _, lic := range a.Licenses {
			val := lic.SPDXExpression
			if val == "" {
				val = lic.Value
			}
			if val != "" {
				comp.Licenses = append(comp.Licenses, val)
			}
		}
		for _, cpe := range a.CPEs {
			if cpe.CPE != "" {
				comp.CPEs = append(comp.CPEs, cpe.CPE)
			}
		}
		// Compute ID using identity matcher
		comp.ID = identity.ComputeID(comp.ToIdentity())

		if a.SyftID != "" {
			syftIDToIdx[a.SyftID] = len(comps)
		}
		comps = append(comps, comp)
	}

	// Resolve dependency-of relationships from artifactRelationships
	depMap := make(map[int][]string) // parent comp index → child comp IDs
	for _, rel := range doc.ArtifactRelationships {
		if rel.Type != "dependency-of" {
			continue
		}
		parentIdx, parentOK := syftIDToIdx[rel.Parent]
		childIdx, childOK := syftIDToIdx[rel.Child]
		if parentOK && childOK {
			depMap[parentIdx] = append(depMap[parentIdx], comps[childIdx].ID)
		}
	}
	for idx, deps := range depMap {
		comps[idx].Dependencies = deps
	}

	return comps, info, nil
}
