package sbom

import (
	"encoding/json"

	"github.com/rezmoss/sbomlyze/internal/identity"
)

// SBOMInfo holds SBOM source metadata.
type SBOMInfo struct {
	OSName             string         `json:"os_name,omitempty"`
	OSVersion          string         `json:"os_version,omitempty"`
	OSPrettyName       string         `json:"os_pretty_name,omitempty"`
	OSVersionID        string         `json:"os_version_id,omitempty"` // os-release VERSION_ID, e.g. 12.10
	OSIDLike           []string       `json:"os_id_like,omitempty"`
	SourceType         string         `json:"source_type,omitempty"`
	SourceName         string         `json:"source_name,omitempty"`
	SourceID           string         `json:"source_id,omitempty"`
	SourceVersion      string         `json:"source_version,omitempty"` // e.g. image digest
	RelationshipCounts map[string]int `json:"relationship_counts,omitempty"`
	ToolName           string         `json:"tool_name,omitempty"`
	ToolVersion        string         `json:"tool_version,omitempty"`
	SchemaVersion      string         `json:"schema_version,omitempty"`
	SBOMTimestamp      string         `json:"sbom_timestamp,omitempty"`
	Format             string         `json:"format,omitempty"`       // CycloneDX, SPDX, Syft JSON
	SpecVersion        string         `json:"spec_version,omitempty"` // e.g. 1.6, SPDX-2.3
	SBOMAuthor         string         `json:"sbom_author,omitempty"`
	SearchScope        string         `json:"search_scope,omitempty"`
	FilesCount         int            `json:"files_count,omitempty"`
	// file inventory (Syft JSON, SPDX); not output
	Files []FileEntry `json:"-"`
}

// Component is a normalized SBOM component.
type Component struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	PURL         string            `json:"purl,omitempty"`
	Licenses     []string          `json:"licenses,omitempty"`
	CPEs         []string          `json:"cpes,omitempty"`
	Hashes       map[string]string `json:"hashes,omitempty"`
	Digests      map[string]string `json:"digests,omitempty"` // extra pkg digests by kind (go-h1, cargo-checksum)
	Dependencies []string          `json:"dependencies,omitempty"`
	DepsDeclared bool              `json:"-"` // deps declared by format, even if empty
	BOMRef       string            `json:"bom-ref,omitempty"`
	SPDXID       string            `json:"spdxid,omitempty"`
	Namespace    string            `json:"namespace,omitempty"`
	Supplier     string            `json:"supplier,omitempty"`
	Language     string            `json:"language,omitempty"`  // lang
	FoundBy      string            `json:"foundBy,omitempty"`   // scanner
	Type         string            `json:"type,omitempty"`      // pkg type
	Locations    []string          `json:"locations,omitempty"` // file paths
	RawJSON      json.RawMessage   `json:"-"`                   // original JSON, excluded from output
	// license.name entries; never SPDX-valid
	NonSPDXLicenses []string `json:"-"`
	// Syft primary-evidence locations
	PrimaryLocations []string `json:"-"`
	// owned file paths (contains/CONTAINS); may be shared
	OwnedFiles []string `json:"-"`
	// dpkg conffiles; ConfigKnown false if no flag
	ConfigFiles []string `json:"-"`
	ConfigKnown bool     `json:"-"`
	// Syft package type (rust-crate, go-module); ecosystem w/o PURL
	PkgType string `json:"-"`
}

// Digest kinds stored in Component.Digests.
const (
	DigestGoH1          = "go-h1"          // Go module h1 checksum (go.sum)
	DigestCargoChecksum = "cargo-checksum" // Cargo.lock crate checksum
)

// IsEvidence: file/os entries, not packages
func (c Component) IsEvidence() bool {
	return c.Type == "file" || c.Type == "operating-system"
}

// DigestSet: Hashes + Digests, keyed by kind
func (c Component) DigestSet() map[string]string {
	if len(c.Digests) == 0 {
		return c.Hashes
	}
	out := make(map[string]string, len(c.Hashes)+len(c.Digests))
	for k, v := range c.Hashes {
		out[k] = v
	}
	for k, v := range c.Digests {
		out[k] = v
	}
	return out
}

// PackageComponents drops file/os entries — they're evidence, not packages.
func PackageComponents(comps []Component) []Component {
	out := make([]Component, 0, len(comps))
	for _, c := range comps {
		if c.IsEvidence() {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ToIdentity converts to ComponentIdentity.
func (c Component) ToIdentity() identity.ComponentIdentity {
	// OS bom-ref embeds the version (os:debian@12.10)
	if c.Type == "operating-system" && c.PURL == "" && len(c.CPEs) == 0 {
		return identity.ComponentIdentity{Name: "os:" + c.Name}
	}
	return identity.ComponentIdentity{
		PURL:      c.PURL,
		CPEs:      c.CPEs,
		BOMRef:    c.BOMRef,
		SPDXID:    c.SPDXID,
		Namespace: c.Namespace,
		Name:      c.Name,
	}
}

// ComputeID returns the canonical ID.
func (c *Component) ComputeID() string {
	return identity.ComputeID(c.ToIdentity())
}
