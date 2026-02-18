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
	OSIDLike           []string       `json:"os_id_like,omitempty"`
	SourceType         string         `json:"source_type,omitempty"`
	SourceName         string         `json:"source_name,omitempty"`
	SourceID           string         `json:"source_id,omitempty"`
	RelationshipCounts map[string]int `json:"relationship_counts,omitempty"`
	ToolName           string         `json:"tool_name,omitempty"`
	ToolVersion        string         `json:"tool_version,omitempty"`
	SchemaVersion      string         `json:"schema_version,omitempty"`
	SearchScope        string         `json:"search_scope,omitempty"`
	FilesCount         int            `json:"files_count,omitempty"`
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
	Dependencies []string          `json:"dependencies,omitempty"`
	BOMRef       string            `json:"bom-ref,omitempty"`
	SPDXID       string            `json:"spdxid,omitempty"`
	Namespace    string            `json:"namespace,omitempty"`
	Supplier     string            `json:"supplier,omitempty"`
	Language     string            `json:"language,omitempty"`  // lang
	FoundBy      string            `json:"foundBy,omitempty"`  // scanner
	Type         string            `json:"type,omitempty"`     // pkg type
	Locations    []string          `json:"locations,omitempty"` // file paths
	RawJSON      json.RawMessage   `json:"-"`                  // original JSON, excluded from output
}

// ToIdentity converts to ComponentIdentity.
func (c Component) ToIdentity() identity.ComponentIdentity {
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
