package sbom

import (
	"encoding/json"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/identity"
)

// ParseSyft parses Syft JSON.
func ParseSyft(data []byte) ([]Component, error) {
	comps, _, err := ParseSyftWithInfo(data)
	return comps, err
}

// ParseSyftWithInfo parses Syft JSON with metadata.
func ParseSyftWithInfo(data []byte) ([]Component, SBOMInfo, error) {
	var doc struct {
		Artifacts             []json.RawMessage `json:"artifacts"`
		ArtifactRelationships []struct {
			Parent string `json:"parent"`
			Child  string `json:"child"`
			Type   string `json:"type"`
		} `json:"artifactRelationships"`
		Source     json.RawMessage `json:"source"` // RawMessage to handle missing/malformed
		Distro     json.RawMessage `json:"distro"` // RawMessage to handle object or array
		Files      json.RawMessage `json:"files"`
		Descriptor struct {
			Name          string `json:"name"`
			Version       string `json:"version"`
			Configuration struct {
				Search struct {
					Scope string `json:"scope"`
				} `json:"search"`
			} `json:"configuration"`
		} `json:"descriptor"`
		Schema struct {
			Version string `json:"version"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, SBOMInfo{}, err
	}

	info := SBOMInfo{Format: "Syft JSON", SpecVersion: doc.Schema.Version}
	info.ToolName = doc.Descriptor.Name
	info.ToolVersion = doc.Descriptor.Version
	info.SchemaVersion = doc.Schema.Version
	info.SearchScope = doc.Descriptor.Configuration.Search.Scope

	if len(doc.Files) > 2 {
		var filesArr []json.RawMessage
		if json.Unmarshal(doc.Files, &filesArr) == nil {
			info.FilesCount = len(filesArr)
		}
	}

	if len(doc.Source) > 0 {
		var sourceInfo struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Type   string `json:"type"`
			Target struct {
				UserInput string `json:"userInput"`
			} `json:"target"`
		}
		if err := json.Unmarshal(doc.Source, &sourceInfo); err == nil {
			info.SourceType = sourceInfo.Type
			info.SourceName = sourceInfo.Target.UserInput
			if info.SourceName == "" {
				info.SourceName = sourceInfo.Name
			}
			info.SourceID = sourceInfo.ID
		}
	}

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
		}
		info.OSName = distroInfo.Name
		info.OSVersion = distroInfo.Version
		info.OSPrettyName = distroInfo.PrettyName
		info.OSIDLike = distroInfo.IDLike
		if info.OSName == "" && distroInfo.ID != "" {
			info.OSName = distroInfo.ID
		}
	}

	syftIDToIdx := make(map[string]int)

	var comps []Component
	for _, rawArtifact := range doc.Artifacts {
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
			Locations    []struct {
				Path        string `json:"path"`
				Annotations struct {
					Evidence string `json:"evidence"`
				} `json:"annotations"`
			} `json:"locations"`
			Licenses []struct {
				Value          string `json:"value"`
				SPDXExpression string `json:"spdxExpression"`
			} `json:"licenses"`
			CPEs []struct {
				CPE string `json:"cpe"`
			} `json:"cpes"`
		}
		if err := json.Unmarshal(rawArtifact, &a); err != nil {
			continue
		}

		comp := Component{
			Name:     a.Name,
			Version:  a.Version,
			PURL:     a.PURL,
			Type:     a.Type,
			Language: a.Language,
			FoundBy:  a.FoundBy,
			Hashes:   make(map[string]string),
			RawJSON:  rawArtifact,
		}
		for _, loc := range a.Locations {
			if loc.Path != "" {
				comp.Locations = append(comp.Locations, loc.Path)
				if loc.Annotations.Evidence == "primary" {
					comp.PrimaryLocations = append(comp.PrimaryLocations, loc.Path)
				}
			}
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

		extractSyftHashes(a.MetadataType, a.Metadata, comp.Hashes)
		comp.Digests = extractSyftDigests(a.MetadataType, a.Metadata)
		comp.Supplier = extractSyftMaintainer(a.Metadata)

		comp.ID = identity.ComputeID(comp.ToIdentity())

		if a.SyftID != "" {
			syftIDToIdx[a.SyftID] = len(comps)
		}
		comps = append(comps, comp)
	}

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

// extractSyftMaintainer: metadata.maintainer (apk/dpkg etc.) -> supplier
func extractSyftMaintainer(metadata json.RawMessage) string {
	if len(metadata) == 0 {
		return ""
	}
	var md struct {
		Maintainer string `json:"maintainer"`
	}
	if json.Unmarshal(metadata, &md) != nil {
		return ""
	}
	return strings.TrimSpace(md.Maintainer)
}

// extractSyftDigests reads package checksums that are not artifact hashes:
// Go module h1 (go.sum) and the Cargo.lock crate checksum.
func extractSyftDigests(metadataType string, metadata json.RawMessage) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	switch metadataType {
	case "go-module-entry", "go-module-buildinfo-entry", "rust-cargo-lock-entry":
	default:
		return nil
	}
	var md struct {
		H1Digest string `json:"h1Digest"`
		Checksum string `json:"checksum"`
	}
	if json.Unmarshal(metadata, &md) != nil {
		return nil
	}
	var out map[string]string
	if md.H1Digest != "" {
		out = map[string]string{DigestGoH1: md.H1Digest}
	}
	if md.Checksum != "" {
		if out == nil {
			out = make(map[string]string, 1)
		}
		out[DigestCargoChecksum] = md.Checksum
	}
	return out
}

// extractSyftHashes extracts hashes from Syft metadata.
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
			if algo, hash, ok := strings.Cut(md.Integrity, "-"); ok {
				hashes[strings.ToUpper(algo)] = hash
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
