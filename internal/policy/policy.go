package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/compliance"
)

// Policy defines SBOM diff rules. doc tags feed the website.
type Policy struct {
	MaxAdded   int `json:"max_added,omitempty" doc:"Maximum new components allowed (0 = unlimited)"`
	MaxRemoved int `json:"max_removed,omitempty" doc:"Maximum removed components allowed"`
	MaxChanged int `json:"max_changed,omitempty" doc:"Maximum changed packages allowed"`

	DenyLicenses    []string `json:"deny_licenses,omitempty" doc:"Forbidden license identifiers"`
	RequireLicenses bool     `json:"require_licenses,omitempty" doc:"Require all added components to have licenses"`

	DenyDuplicates bool `json:"deny_duplicates,omitempty" doc:"Fail if duplicate packages exist in the result"`

	DenyIntegrityDrift bool `json:"deny_integrity_drift,omitempty" doc:"Fail if a package digest changed without a version change"`
	MaxDepth           int  `json:"max_depth,omitempty" doc:"Fail if new transitive dependencies reach depth >= N"`
	// fail on same-ver owned-file changes; config skipped
	DenyOwnedFileDrift          bool `json:"deny_owned_file_drift,omitempty" doc:"Fail if a package kept its version while files it owns changed (Syft JSON, SPDX)"`
	OwnedFileDriftIncludeConfig bool `json:"owned_file_drift_include_config,omitempty" doc:"Also fail deny_owned_file_drift on dpkg config files"`

	// Warning rules - these produce warnings, not failures
	WarnSupplierChange bool `json:"warn_supplier_change,omitempty" doc:"Warn, not fail, if a supplier or author changed"`
	WarnNewTransitive  bool `json:"warn_new_transitive,omitempty" doc:"Warn on any new transitive dependencies"`

	MinNTIAScore         int `json:"min_ntia_score,omitempty" doc:"Fail below this NTIA score (0-100)"`
	MinCISAScore         int `json:"min_cisa_score,omitempty" doc:"Fail below this CISA score (0-100)"`
	MinBSIScore          int `json:"min_bsi_score,omitempty" doc:"Fail below this BSI TR-03183 score (0-100)"`
	MinOverallCompliance int `json:"min_overall_compliance,omitempty" doc:"Fail below this overall compliance score (0-100)"`
}

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Violation is a policy rule violation.
type Violation struct {
	Rule     string   `json:"rule"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

// Load parses a policy from JSON.
func Load(data []byte) (Policy, error) {
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// Evaluate checks a diff against policy rules.
func Evaluate(policy Policy, result analysis.DiffResult) []Violation {
	var violations []Violation

	if policy.MaxAdded > 0 && len(result.Added) > policy.MaxAdded {
		violations = append(violations, Violation{
			Rule:     "max_added",
			Message:  fmt.Sprintf("added %d > max %d", len(result.Added), policy.MaxAdded),
			Severity: SeverityError,
		})
	}

	if policy.MaxRemoved > 0 && len(result.Removed) > policy.MaxRemoved {
		violations = append(violations, Violation{
			Rule:     "max_removed",
			Message:  fmt.Sprintf("removed %d > max %d", len(result.Removed), policy.MaxRemoved),
			Severity: SeverityError,
		})
	}

	if policy.MaxChanged > 0 && len(result.Changed) > policy.MaxChanged {
		violations = append(violations, Violation{
			Rule:     "max_changed",
			Message:  fmt.Sprintf("changed %d > max %d", len(result.Changed), policy.MaxChanged),
			Severity: SeverityError,
		})
	}

	if len(policy.DenyLicenses) > 0 {
		denySet := make(map[string]bool)
		for _, lic := range policy.DenyLicenses {
			denySet[lic] = true
		}

		for _, comp := range result.Added {
			for _, lic := range comp.Licenses {
				if denySet[lic] {
					violations = append(violations, Violation{
						Rule:     "deny_licenses",
						Message:  fmt.Sprintf("%s: denied license %s", comp.Name, lic),
						Severity: SeverityError,
					})
				}
			}
		}
	}

	if policy.RequireLicenses {
		for _, comp := range result.Added {
			if len(comp.Licenses) == 0 {
				violations = append(violations, Violation{
					Rule:     "require_licenses",
					Message:  fmt.Sprintf("%s: no license", comp.Name),
					Severity: SeverityError,
				})
			}
		}
	}

	if policy.DenyDuplicates && result.Duplicates != nil {
		if len(result.Duplicates.After) > 0 {
			violations = append(violations, Violation{
				Rule:     "deny_duplicates",
				Message:  fmt.Sprintf("%d duplicates found", len(result.Duplicates.After)),
				Severity: SeverityError,
			})
		}
	}

	if policy.DenyIntegrityDrift && result.DriftSummary != nil {
		if result.DriftSummary.IntegrityDrift > 0 {
			for _, changed := range result.Changed {
				if changed.Drift != nil && changed.Drift.Type == analysis.DriftTypeIntegrity {
					violations = append(violations, Violation{
						Rule:     "deny_integrity_drift",
						Message:  fmt.Sprintf("%s%s: hash changed without version change", changed.Name, atLocation(changed.Location)),
						Severity: SeverityError,
					})
				}
			}
		}
	}

	if policy.DenyOwnedFileDrift {
		for _, d := range result.OwnedFileDrift {
			files := d.GatedFiles(policy.OwnedFileDriftIncludeConfig)
			if len(files) == 0 {
				continue
			}
			paths := make([]string, 0, min(len(files), 5))
			for _, f := range files[:min(len(files), 5)] {
				paths = append(paths, f.Change+" "+f.Path)
			}
			msg := fmt.Sprintf("%s %s: %d owned files changed without a version change (%s", d.Name, d.Version, len(files), strings.Join(paths, ", "))
			if len(files) > len(paths) {
				msg += fmt.Sprintf(", +%d more", len(files)-len(paths))
			}
			violations = append(violations, Violation{
				Rule:     "deny_owned_file_drift",
				Message:  msg + ")",
				Severity: SeverityError,
			})
		}
	}

	if policy.MaxDepth > 0 && result.Dependencies != nil && result.Dependencies.DepthSummary != nil {
		var violatingDeps []string
		for _, td := range result.Dependencies.TransitiveNew {
			if td.Depth >= policy.MaxDepth {
				violatingDeps = append(violatingDeps, fmt.Sprintf("%s (depth %d)", td.Target, td.Depth))
			}
		}
		if len(violatingDeps) > 0 {
			violations = append(violations, Violation{
				Rule:     "max_depth",
				Message:  fmt.Sprintf("transitive deps at depth >= %d: %v", policy.MaxDepth, violatingDeps),
				Severity: SeverityError,
			})
		}
	}

	if policy.WarnSupplierChange {
		for _, changed := range result.Changed {
			if changed.Before.Supplier != changed.After.Supplier &&
				(changed.Before.Supplier != "" || changed.After.Supplier != "") {
				violations = append(violations, Violation{
					Rule:     "warn_supplier_change",
					Message:  fmt.Sprintf("%s: supplier %q -> %q", changed.Name, changed.Before.Supplier, changed.After.Supplier),
					Severity: SeverityWarning,
				})
			}
		}
	}

	if policy.WarnNewTransitive && result.Dependencies != nil {
		if len(result.Dependencies.TransitiveNew) > 0 {
			violations = append(violations, Violation{
				Rule:     "warn_new_transitive",
				Message:  fmt.Sprintf("%d new transitive deps", len(result.Dependencies.TransitiveNew)),
				Severity: SeverityWarning,
			})
		}
	}

	return violations
}

// HasComplianceRules: any score threshold set. Auto-enables eval so thresholds
// hold without the --compliance flag.
func HasComplianceRules(p Policy) bool {
	return p.MinNTIAScore > 0 || p.MinCISAScore > 0 || p.MinBSIScore > 0 || p.MinOverallCompliance > 0
}

// EvaluateCompliance checks a compliance report against policy score thresholds.
// This allows CI to enforce minimum SBOM quality levels per standard.
// Fail-closed: a nil framework result is treated as score 0, so thresholds
// cannot be bypassed by feeding an SBOM that fails to parse.
func EvaluateCompliance(pol Policy, report compliance.Report) []Violation {
	var violations []Violation

	if pol.MinNTIAScore > 0 && scoreOf(report.NTIA) < pol.MinNTIAScore {
		violations = append(violations, newScoreViolation(
			"min_ntia_score", "NTIA", scoreOf(report.NTIA), pol.MinNTIAScore, report.NTIA,
		))
	}

	if pol.MinCISAScore > 0 && scoreOf(report.CISA) < pol.MinCISAScore {
		violations = append(violations, newScoreViolation(
			"min_cisa_score", "CISA", scoreOf(report.CISA), pol.MinCISAScore, report.CISA,
		))
	}

	if pol.MinBSIScore > 0 && scoreOf(report.BSI) < pol.MinBSIScore {
		violations = append(violations, newScoreViolation(
			"min_bsi_score", "BSI TR-03183", scoreOf(report.BSI), pol.MinBSIScore, report.BSI,
		))
	}

	if pol.MinOverallCompliance > 0 && report.Overall < pol.MinOverallCompliance {
		violations = append(violations, Violation{
			Rule:     "min_overall_compliance",
			Message:  fmt.Sprintf("overall compliance score %d < minimum %d", report.Overall, pol.MinOverallCompliance),
			Severity: SeverityError,
		})
	}

	return violations
}

// scoreOf returns the framework score, or 0 if the framework result is nil.
func scoreOf(r *compliance.FrameworkResult) int {
	if r == nil {
		return 0
	}
	return r.Score
}

// newScoreViolation builds a Violation for a threshold breach. When the
// framework result is nil it emits an explicit "not evaluated" message so CI
// logs make the reason obvious.
func newScoreViolation(rule, framework string, got, want int, r *compliance.FrameworkResult) Violation {
	if r == nil {
		return Violation{
			Rule:     rule,
			Message:  fmt.Sprintf("%s compliance not evaluated (score 0) < minimum %d", framework, want),
			Severity: SeverityError,
		}
	}
	return Violation{
		Rule:     rule,
		Message:  fmt.Sprintf("%s compliance score %d < minimum %d (%d/%d checks passed)", framework, got, want, r.Passed, r.Total),
		Severity: SeverityError,
	}
}

func HasErrors(violations []Violation) bool {
	for _, v := range violations {
		if v.Severity == SeverityError {
			return true
		}
	}
	return false
}

func atLocation(loc string) string {
	if loc == "" {
		return ""
	}
	return " @ " + loc
}
