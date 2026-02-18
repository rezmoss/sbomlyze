package convert

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

type syftDocument struct {
	Artifacts             []syftArtifact      `json:"artifacts"`
	ArtifactRelationships []syftRelationship  `json:"artifactRelationships"`
	Files                 []any               `json:"files"`
	Source                syftSource          `json:"source"`
	Distro                syftDistro          `json:"distro"`
	Descriptor            syftDescriptor      `json:"descriptor"`
	Schema                syftSchema          `json:"schema"`
}

type syftArtifact struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	Type      string         `json:"type"`
	FoundBy   string         `json:"foundBy"`
	Locations []syftLocation `json:"locations"`
	Licenses  []syftLicense  `json:"licenses"`
	Language  string         `json:"language"`
	CPEs      []syftCPE      `json:"cpes"`
	PURL      string         `json:"purl"`
}

type syftLocation struct {
	Path string `json:"path"`
}

type syftLicense struct {
	Value          string `json:"value"`
	SPDXExpression string `json:"spdxExpression"`
}

type syftCPE struct {
	CPE string `json:"cpe"`
}

type syftRelationship struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
	Type   string `json:"type"`
}

type syftSource struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Type   string      `json:"type"`
	Target any `json:"target"`
}

type syftDistro struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	PrettyName string   `json:"prettyName"`
	IDLike     []string `json:"idLike"`
}

type syftDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type syftSchema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

// Syft JSON output
func WriteSyft(w io.Writer, comps []sbom.Component, info sbom.SBOMInfo) error {
	doc := syftDocument{
		Artifacts:             make([]syftArtifact, 0, len(comps)),
		ArtifactRelationships: make([]syftRelationship, 0),
		Files:                 make([]any, 0),
		Source: syftSource{
			ID:   info.SourceID,
			Name: info.SourceName,
			Type: info.SourceType,
		},
		Distro: syftDistro{
			Name:       info.OSName,
			Version:    info.OSVersion,
			PrettyName: info.OSPrettyName,
			IDLike:     info.OSIDLike,
		},
		Descriptor: syftDescriptor{
			Name:    "sbomlyze",
			Version: "convert",
		},
		Schema: syftSchema{
			Version: "16.0.16",
			URL:     "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.16.json",
		},
	}

	idToArtifactID := make(map[string]string, len(comps))

	for i, c := range comps {
		a := componentToSyftArtifact(c, i)
		doc.Artifacts = append(doc.Artifacts, a)
		idToArtifactID[c.ID] = a.ID
	}

	for _, c := range comps {
		parentID, ok := idToArtifactID[c.ID]
		if !ok {
			continue
		}
		for _, depID := range c.Dependencies {
			childID, ok := idToArtifactID[depID]
			if !ok {
				continue
			}
			doc.ArtifactRelationships = append(doc.ArtifactRelationships, syftRelationship{
				Parent: parentID,
				Child:  childID,
				Type:   "dependency-of",
			})
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func componentToSyftArtifact(c sbom.Component, index int) syftArtifact {
	a := syftArtifact{
		ID:      syftArtifactID(c, index),
		Name:    c.Name,
		Version: c.Version,
		Type:    syftTypeFor(c),
		FoundBy: c.FoundBy,
		PURL:    c.PURL,
		Language: c.Language,
	}

	locs := make([]syftLocation, 0, len(c.Locations))
	for _, loc := range c.Locations {
		locs = append(locs, syftLocation{Path: loc})
	}
	a.Locations = locs

	lics := make([]syftLicense, 0, len(c.Licenses))
	for _, lic := range c.Licenses {
		lics = append(lics, syftLicense{
			Value:          lic,
			SPDXExpression: lic,
		})
	}
	a.Licenses = lics

	cpes := make([]syftCPE, 0, len(c.CPEs))
	for _, cpe := range c.CPEs {
		cpes = append(cpes, syftCPE{CPE: cpe})
	}
	a.CPEs = cpes

	return a
}

func syftArtifactID(c sbom.Component, index int) string {
	if c.BOMRef != "" {
		return c.BOMRef
	}
	if c.PURL != "" {
		return c.PURL
	}
	if c.Name != "" {
		if c.Version != "" {
			return c.Name + "-" + c.Version
		}
		return c.Name
	}
	return fmt.Sprintf("artifact-%d", index)
}

// infer pkg type from PURL scheme
func syftTypeFor(c sbom.Component) string {
	if c.Type != "" {
		return c.Type
	}
	if c.PURL != "" {
		purl := strings.TrimPrefix(c.PURL, "pkg:")
		if scheme, _, ok := strings.Cut(purl, "/"); ok && scheme != "" {
			switch scheme {
			case "npm":
				return "npm"
			case "pypi":
				return "python"
			case "gem":
				return "gem"
			case "maven":
				return "java-archive"
			case "golang":
				return "go-module"
			case "cargo":
				return "rust-crate"
			case "rpm":
				return "rpm"
			case "deb":
				return "deb"
			case "apk":
				return "apk"
			case "nuget":
				return "dotnet"
			case "cocoapods":
				return "pod"
			case "hex":
				return "hex"
			case "composer":
				return "php-composer"
			}
		}
	}
	return "unknown"
}
