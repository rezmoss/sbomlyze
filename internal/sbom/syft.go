package sbom

import (
	"encoding/json"

	"github.com/rezmoss/sbomlyze/internal/identity"
)

// ParseSyft parses Syft format SBOM data
func ParseSyft(data []byte) ([]Component, error) {
	// First, get raw artifacts to preserve original JSON
	var rawDoc struct {
		Artifacts []json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		return nil, err
	}

	var comps []Component
	for _, rawArtifact := range rawDoc.Artifacts {
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
	return comps, nil
}
