package sbom

import (
	"encoding/json"

	"github.com/rezmoss/sbomlyze/internal/identity"
)

// SBOMInfo holds metadata about the SBOM source (OS, distro, source type)
type SBOMInfo struct {
	OSName     string `json:"os_name,omitempty"`
	OSVersion  string `json:"os_version,omitempty"`
	SourceType string `json:"source_type,omitempty"` // e.g., "image", "directory", "file"
	SourceName string `json:"source_name,omitempty"` // e.g., "alpine:latest", "/path/to/dir"
}

// Component represents a normalized component from any SBOM format
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
	Language     string            `json:"language,omitempty"`  // Programming language (go, python, java, etc.)
	FoundBy      string            `json:"foundBy,omitempty"`   // Scanner/cataloger that found this component
	Type         string            `json:"type,omitempty"`      // Package type from SBOM (e.g., library, application)
	RawJSON      json.RawMessage   `json:"-"`                   // Original JSON from SBOM, excluded from output
}

// ToIdentity converts a Component to a ComponentIdentity for ID computation
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

// ComputeID computes the canonical ID for this component
func (c *Component) ComputeID() string {
	return identity.ComputeID(c.ToIdentity())
}
