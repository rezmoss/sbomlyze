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
	// Parse document structure including source and distro info
	var doc struct {
		Artifacts []json.RawMessage `json:"artifacts"`
		Source    struct {
			Type   string `json:"type"`
			Target struct {
				UserInput string `json:"userInput"`
			} `json:"target"`
		} `json:"source"`
		Distro struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			ID      string `json:"id"`
		} `json:"distro"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, SBOMInfo{}, err
	}

	// Extract SBOM info
	info := SBOMInfo{
		SourceType: doc.Source.Type,
		SourceName: doc.Source.Target.UserInput,
		OSName:     doc.Distro.Name,
		OSVersion:  doc.Distro.Version,
	}
	// If distro name is empty but ID is set, use ID
	if info.OSName == "" && doc.Distro.ID != "" {
		info.OSName = doc.Distro.ID
	}

	var comps []Component
	for _, rawArtifact := range doc.Artifacts {
		// Parse the artifact for our normalized fields
		var a struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Licenses []struct {
				Value string `json:"value"`
			} `json:"licenses"`
			CPEs []struct {
				CPE string `json:"cpe"`
			} `json:"cpes"`
			Metadata struct {
				PullDependencies []string `json:"pullDependencies"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(rawArtifact, &a); err != nil {
			continue // Skip malformed artifacts
		}

		comp := Component{
			Name:         a.Name,
			Version:      a.Version,
			PURL:         a.PURL,
			Hashes:       make(map[string]string),
			Dependencies: a.Metadata.PullDependencies,
			RawJSON:      rawArtifact, // Preserve the original JSON
		}
		for _, lic := range a.Licenses {
			if lic.Value != "" {
				comp.Licenses = append(comp.Licenses, lic.Value)
			}
		}
		for _, cpe := range a.CPEs {
			if cpe.CPE != "" {
				comp.CPEs = append(comp.CPEs, cpe.CPE)
			}
		}
		// Compute ID using identity matcher
		comp.ID = identity.ComputeID(comp.ToIdentity())
		comps = append(comps, comp)
	}
	return comps, info, nil
}
