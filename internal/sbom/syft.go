package sbom

import (
	"encoding/json"
	"strings"

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
		Source     json.RawMessage `json:"source"` // RawMessage to handle missing/malformed
		Distro     json.RawMessage `json:"distro"` // RawMessage to handle object or array
		Descriptor struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"descriptor"`
		Schema struct {
			Version string `json:"version"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, SBOMInfo{}, err
	}

	var info SBOMInfo
	info.ToolName = doc.Descriptor.Name
	info.ToolVersion = doc.Descriptor.Version
	info.SchemaVersion = doc.Schema.Version

	// Parse source flexibly - ignore errors, just use empty values
	if len(doc.Source) > 0 {
		var sourceInfo struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
			Target struct {
				UserInput string `json:"userInput"`
			} `json:"target"`
		}
		if err := json.Unmarshal(doc.Source, &sourceInfo); err == nil {
			info.SourceType = sourceInfo.Type
			// Prefer target.userInput (image scans), fall back to source.name (filesystem scans)
			info.SourceName = sourceInfo.Target.UserInput
			if info.SourceName == "" {
				info.SourceName = sourceInfo.Name
			}
			info.SourceID = sourceInfo.ID
		}
		// If parsing fails, continue with empty source info
	}

	// Parse distro flexibly - can be object or array, ignore errors
	if len(doc.Distro) > 0 {
		var distroInfo struct {
			Name       string   `json:"name"`
			PrettyName string   `json:"prettyName"`
			Version    string   `json:"version"`
			ID         string   `json:"id"`
			IDLike     []string `json:"idLike"`
		}
		// Try parsing as object first
		if err := json.Unmarshal(doc.Distro, &distroInfo); err != nil {
			// Try parsing as array and take first element
			var distroArray []struct {
				Name       string   `json:"name"`
				PrettyName string   `json:"prettyName"`
				Version    string   `json:"version"`
				ID         string   `json:"id"`
				IDLike     []string `json:"idLike"`
			}
			if err := json.Unmarshal(doc.Distro, &distroArray); err == nil && len(distroArray) > 0 {
				distroInfo = distroArray[0]
			}
			// If both fail, continue with empty distro info
		}
		info.OSName = distroInfo.Name
		info.OSVersion = distroInfo.Version
		info.OSPrettyName = distroInfo.PrettyName
		info.OSIDLike = distroInfo.IDLike
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
			SyftID       string          `json:"id"`
			Name         string          `json:"name"`
			Version      string          `json:"version"`
			PURL         string          `json:"purl"`
			Type         string          `json:"type"`
			Language     string          `json:"language"`
			FoundBy      string          `json:"foundBy"`
			MetadataType string          `json:"metadataType"`
			Metadata     json.RawMessage `json:"metadata"`
			Licenses     []struct {
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

		// Extract hashes from type-specific metadata
		extractSyftHashes(a.MetadataType, a.Metadata, comp.Hashes)

		// Compute ID using identity matcher
		comp.ID = identity.ComputeID(comp.ToIdentity())

		if a.SyftID != "" {
			syftIDToIdx[a.SyftID] = len(comps)
		}
		comps = append(comps, comp)
	}

	// Process all artifact relationships: count by type + resolve dependency-of
	relCounts := make(map[string]int)
	depMap := make(map[int][]string) // parent comp index → child comp IDs
	for _, rel := range doc.ArtifactRelationships {
		if rel.Type != "" {
			relCounts[rel.Type]++
		}
		if rel.Type == "dependency-of" {
			parentIdx, parentOK := syftIDToIdx[rel.Parent]
			childIdx, childOK := syftIDToIdx[rel.Child]
			if parentOK && childOK {
				depMap[parentIdx] = append(depMap[parentIdx], comps[childIdx].ID)
			}
		}
	}
	for idx, deps := range depMap {
		comps[idx].Dependencies = deps
	}
	if len(relCounts) > 0 {
		info.RelationshipCounts = relCounts
	}

	return comps, info, nil
}

// extractSyftHashes extracts hash/digest information from Syft metadata into the hashes map.
// Different metadata types store hashes in different fields.
func extractSyftHashes(metadataType string, metadata json.RawMessage, hashes map[string]string) {
	if len(metadata) == 0 {
		return
	}

	switch metadataType {
	case "java-archive":
		// metadata.digest: [{algorithm, value}]
		var md struct {
			Digest []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"digest"`
		}
		if json.Unmarshal(metadata, &md) == nil {
			for _, d := range md.Digest {
				if d.Algorithm != "" && d.Value != "" {
					hashes[strings.ToUpper(d.Algorithm)] = d.Value
				}
			}
		}

	case "javascript-npm-package-lock-entry":
		// metadata.integrity: "sha512-base64..."
		var md struct {
			Integrity string `json:"integrity"`
		}
		if json.Unmarshal(metadata, &md) == nil && md.Integrity != "" {
			// Format: "sha512-XXXX" or "sha256-XXXX"
			if idx := strings.Index(md.Integrity, "-"); idx != -1 {
				algo := strings.ToUpper(md.Integrity[:idx])
				hashes[algo] = md.Integrity[idx+1:]
			} else {
				hashes["INTEGRITY"] = md.Integrity
			}
		}

	case "rpm-db-entry", "rpm-archive", "python-package":
		// metadata.files[].digest: {algorithm, value} — use first non-empty
		var md struct {
			Files []struct {
				Digest struct {
					Algorithm string `json:"algorithm"`
					Value     string `json:"value"`
				} `json:"digest"`
			} `json:"files"`
		}
		if json.Unmarshal(metadata, &md) == nil {
			for _, f := range md.Files {
				if f.Digest.Algorithm != "" && f.Digest.Value != "" {
					hashes[strings.ToUpper(f.Digest.Algorithm)] = f.Digest.Value
					break // one representative hash is enough
				}
			}
		}
	}
}
