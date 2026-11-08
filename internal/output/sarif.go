package output

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/policy"
	"github.com/rezmoss/sbomlyze/internal/sbom"
	"github.com/rezmoss/sbomlyze/internal/version"
)

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SARIFMessage     `json:"shortDescription"`
	FullDescription  SARIFMessage     `json:"fullDescription,omitempty"`
	DefaultConfig    SARIFRuleConfig  `json:"defaultConfiguration,omitempty"`
	Help             *SARIFMessage    `json:"help,omitempty"`
	Properties       *SARIFProperties `json:"properties,omitempty"`
}

type SARIFRuleConfig struct {
	Level string `json:"level"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifFingerprint gives GitHub a stable identity for one logical finding.
// Every SBOM result points at the same JSON file without a source region, so
// upload-sarif cannot otherwise distinguish components or policy rules. The
// version suffix follows GitHub's primaryLocationLineHash convention and lets
// us deliberately change the fingerprint algorithm in a future release.
func sarifFingerprint(kind, identity string) map[string]string {
	sum := sha256.Sum256([]byte(kind + "\x00" + identity))
	return map[string]string{
		"primaryLocationLineHash": fmt.Sprintf("%x:1", sum[:16]),
	}
}

// changedIdentity includes location: per-lockfile findings
func changedIdentity(changed analysis.ChangedComponent) string {
	id := changed.ID
	if id == "" {
		id = changed.Name
	}
	if changed.Location != "" {
		id += "\x00" + changed.Location
	}
	return id
}

func componentIdentity(component sbom.Component) string {
	id := component.ID
	if id == "" {
		id = component.PURL
	}
	if id == "" {
		id = component.Name
	}
	// version+location tell occurrences apart
	if len(component.Locations) > 0 {
		id += "\x00" + component.Version + "\x00" + strings.Join(component.Locations, "\x00")
	}
	return id
}

// GenerateSARIF creates a SARIF report.
func GenerateSARIF(result analysis.DiffResult, violations []policy.Violation, sbomFile string) SARIFReport {
	rules := []SARIFRule{
		{
			ID:               "integrity-drift",
			Name:             "Integrity Drift Detected",
			ShortDescription: SARIFMessage{Text: "Component hash changed without version change"},
			DefaultConfig:    SARIFRuleConfig{Level: "error"},
			Properties:       &SARIFProperties{Tags: []string{"security", "supply-chain"}},
		},
		{
			ID:               "owned-file-drift",
			Name:             "Owned File Drift Detected",
			ShortDescription: SARIFMessage{Text: "Files owned by a package changed without a version change"},
			DefaultConfig:    SARIFRuleConfig{Level: "error"},
			Properties:       &SARIFProperties{Tags: []string{"security", "supply-chain"}},
		},
		{
			ID:               "new-component",
			Name:             "New Component Added",
			ShortDescription: SARIFMessage{Text: "A new component was added to the SBOM"},
			DefaultConfig:    SARIFRuleConfig{Level: "note"},
		},
		{
			ID:               "removed-component",
			Name:             "Component Removed",
			ShortDescription: SARIFMessage{Text: "A component was removed from the SBOM"},
			DefaultConfig:    SARIFRuleConfig{Level: "note"},
		},
		{
			ID:               "version-change",
			Name:             "Version Changed",
			ShortDescription: SARIFMessage{Text: "Component version was updated"},
			DefaultConfig:    SARIFRuleConfig{Level: "note"},
		},
		{
			ID:               "deep-dependency",
			Name:             "Deep Transitive Dependency",
			ShortDescription: SARIFMessage{Text: "New dependency introduced at depth 3 or greater"},
			DefaultConfig:    SARIFRuleConfig{Level: "warning"},
			Properties:       &SARIFProperties{Tags: []string{"security", "supply-chain"}},
		},
		{
			ID:               "policy-violation",
			Name:             "Policy Violation",
			ShortDescription: SARIFMessage{Text: "SBOM policy rule was violated"},
			DefaultConfig:    SARIFRuleConfig{Level: "error"},
		},
	}

	results := []SARIFResult{} // empty run is [], not null

	for _, changed := range result.Changed {
		if changed.Drift != nil && changed.Drift.Type == analysis.DriftTypeIntegrity {
			results = append(results, SARIFResult{
				RuleID:              "integrity-drift",
				Level:               "error",
				Message:             SARIFMessage{Text: fmt.Sprintf("Component %s%s has hash change without version change (potential supply chain attack)", changed.Name, atLocation(changed.Location))},
				PartialFingerprints: sarifFingerprint("integrity-drift", changedIdentity(changed)),
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
					},
				}},
			})
		}
	}

	for _, d := range result.OwnedFileDrift {
		level := "error"
		if len(d.GatedFiles(false)) == 0 {
			level = "note" // config files only
		}
		paths := make([]string, 0, len(d.Files))
		for _, f := range d.Files {
			paths = append(paths, f.Change+" "+f.Path)
		}
		results = append(results, SARIFResult{
			RuleID:              "owned-file-drift",
			Level:               level,
			Message:             SARIFMessage{Text: fmt.Sprintf("Package %s %s changed owned files without a version change: %s", d.Name, d.Version, strings.Join(paths, ", "))},
			PartialFingerprints: sarifFingerprint("owned-file-drift", d.ID+"\x00"+d.Version+"\x00"+d.Location),
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
				},
			}},
		})
	}

	if result.Dependencies != nil {
		for _, td := range result.Dependencies.TransitiveNew {
			if td.Depth >= 3 {
				results = append(results, SARIFResult{
					RuleID:              "deep-dependency",
					Level:               "warning",
					Message:             SARIFMessage{Text: fmt.Sprintf("New transitive dependency %s at depth %d", td.Target, td.Depth)},
					PartialFingerprints: sarifFingerprint("deep-dependency", td.Target),
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
						},
					}},
				})
			}
		}
	}

	for _, added := range result.Added {
		results = append(results, SARIFResult{
			RuleID:              "new-component",
			Level:               "note",
			Message:             SARIFMessage{Text: fmt.Sprintf("New component added: %s %s", added.Name, added.Version)},
			PartialFingerprints: sarifFingerprint("new-component", componentIdentity(added)),
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
				},
			}},
		})
	}

	for _, removed := range result.Removed {
		results = append(results, SARIFResult{
			RuleID:              "removed-component",
			Level:               "note",
			Message:             SARIFMessage{Text: fmt.Sprintf("Component removed: %s %s", removed.Name, removed.Version)},
			PartialFingerprints: sarifFingerprint("removed-component", componentIdentity(removed)),
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
				},
			}},
		})
	}

	for _, changed := range result.Changed {
		if changed.Before.Version != changed.After.Version {
			results = append(results, SARIFResult{
				RuleID:              "version-change",
				Level:               "note",
				Message:             SARIFMessage{Text: versionChangeMessage(changed)},
				PartialFingerprints: sarifFingerprint("version-change", changedIdentity(changed)),
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
					},
				}},
			})
		}
	}

	for _, v := range violations {
		level := "error"
		if v.Severity == policy.SeverityWarning {
			level = "warning"
		}
		results = append(results, SARIFResult{
			RuleID:              "policy-violation",
			Level:               level,
			Message:             SARIFMessage{Text: fmt.Sprintf("[%s] %s", v.Rule, v.Message)},
			PartialFingerprints: sarifFingerprint("policy-violation", v.Rule+"\x00"+v.Message),
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
				},
			}},
		})
	}

	return SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "sbomlyze",
					Version:        version.Short(),
					InformationURI: "https://github.com/rezmoss/sbomlyze",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

func versionChangeMessage(c analysis.ChangedComponent) string {
	msg := fmt.Sprintf("Component %s%s version changed: %s -> %s", c.Name, atLocation(c.Location), c.Before.Version, c.After.Version)
	if c.Drift != nil && (c.Drift.Direction == analysis.DirectionDowngrade || c.Drift.Direction == analysis.DirectionUnknown) {
		msg += " (" + c.Drift.Direction + ")"
	}
	return msg
}
