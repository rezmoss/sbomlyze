package output

import (
	"fmt"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/policy"
	"github.com/rezmoss/sbomlyze/internal/version"
)

// SARIF types for GitHub Code Scanning

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
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
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

// GenerateSARIF creates a SARIF report from diff results and policy violations
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

	var results []SARIFResult

	// Add integrity drift results
	for _, changed := range result.Changed {
		if changed.Drift != nil && changed.Drift.Type == analysis.DriftTypeIntegrity {
			results = append(results, SARIFResult{
				RuleID:  "integrity-drift",
				Level:   "error",
				Message: SARIFMessage{Text: fmt.Sprintf("Component %s has hash change without version change (potential supply chain attack)", changed.Name)},
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
					},
				}},
			})
		}
	}

	// Add deep dependency results
	if result.Dependencies != nil {
		for _, td := range result.Dependencies.TransitiveNew {
			if td.Depth >= 3 {
				results = append(results, SARIFResult{
					RuleID:  "deep-dependency",
					Level:   "warning",
					Message: SARIFMessage{Text: fmt.Sprintf("New transitive dependency %s at depth %d", td.Target, td.Depth)},
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
						},
					}},
				})
			}
		}
	}

	// Add policy violations
	for _, v := range violations {
		level := "error"
		if v.Severity == policy.SeverityWarning {
			level = "warning"
		}
		results = append(results, SARIFResult{
			RuleID:  "policy-violation",
			Level:   level,
			Message: SARIFMessage{Text: fmt.Sprintf("[%s] %s", v.Rule, v.Message)},
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
