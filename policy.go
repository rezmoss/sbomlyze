package main

import (
	"encoding/json"
	"fmt"
)

type Policy struct {
	// Component count limits
	MaxAdded   int `json:"max_added,omitempty"`
	MaxRemoved int `json:"max_removed,omitempty"`
	MaxChanged int `json:"max_changed,omitempty"`

	// License rules
	DenyLicenses    []string `json:"deny_licenses,omitempty"`
	RequireLicenses bool     `json:"require_licenses,omitempty"`

	// Duplicate detection
	DenyDuplicates bool `json:"deny_duplicates,omitempty"`

	// Integrity/Security rules (NEW)
	DenyIntegrityDrift bool `json:"deny_integrity_drift,omitempty"` // Fail if hash changed without version
	MaxDepth           int  `json:"max_depth,omitempty"`            // Fail if new transitive deps at depth >= N

	// Warning rules (NEW) - these produce warnings, not failures
	WarnSupplierChange bool `json:"warn_supplier_change,omitempty"` // Warn if supplier/author changed
	WarnNewTransitive  bool `json:"warn_new_transitive,omitempty"`  // Warn on any new transitive deps
}

type PolicySeverity string

const (
	SeverityError   PolicySeverity = "error"
	SeverityWarning PolicySeverity = "warning"
)

type PolicyViolation struct {
	Rule     string         `json:"rule"`
	Message  string         `json:"message"`
	Severity PolicySeverity `json:"severity"`
}

func loadPolicyFromJSON(data []byte) (Policy, error) {
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func evaluatePolicy(policy Policy, result DiffResult) []PolicyViolation {
	var violations []PolicyViolation

	// Check max added
	if policy.MaxAdded > 0 && len(result.Added) > policy.MaxAdded {
		violations = append(violations, PolicyViolation{
			Rule:     "max_added",
			Message:  fmt.Sprintf("too many components added: %d > %d", len(result.Added), policy.MaxAdded),
			Severity: SeverityError,
		})
	}

	// Check max removed
	if policy.MaxRemoved > 0 && len(result.Removed) > policy.MaxRemoved {
		violations = append(violations, PolicyViolation{
			Rule:     "max_removed",
			Message:  fmt.Sprintf("too many components removed: %d > %d", len(result.Removed), policy.MaxRemoved),
			Severity: SeverityError,
		})
	}

	// Check max changed
	if policy.MaxChanged > 0 && len(result.Changed) > policy.MaxChanged {
		violations = append(violations, PolicyViolation{
			Rule:     "max_changed",
			Message:  fmt.Sprintf("too many components changed: %d > %d", len(result.Changed), policy.MaxChanged),
			Severity: SeverityError,
		})
	}

	// Check denied licenses
	if len(policy.DenyLicenses) > 0 {
		denySet := make(map[string]bool)
		for _, lic := range policy.DenyLicenses {
			denySet[lic] = true
		}

		for _, comp := range result.Added {
			for _, lic := range comp.Licenses {
				if denySet[lic] {
					violations = append(violations, PolicyViolation{
						Rule:     "deny_licenses",
						Message:  fmt.Sprintf("component %s has denied license: %s", comp.Name, lic),
						Severity: SeverityError,
					})
				}
			}
		}
	}

	// Check required licenses
	if policy.RequireLicenses {
		for _, comp := range result.Added {
			if len(comp.Licenses) == 0 {
				violations = append(violations, PolicyViolation{
					Rule:     "require_licenses",
					Message:  fmt.Sprintf("component %s has no license", comp.Name),
					Severity: SeverityError,
				})
			}
		}
	}

	// Check duplicates
	if policy.DenyDuplicates && result.Duplicates != nil {
		if len(result.Duplicates.After) > 0 {
			violations = append(violations, PolicyViolation{
				Rule:     "deny_duplicates",
				Message:  fmt.Sprintf("found %d duplicate components in result", len(result.Duplicates.After)),
				Severity: SeverityError,
			})
		}
	}

	// Check integrity drift (NEW)
	if policy.DenyIntegrityDrift && result.DriftSummary != nil {
		if result.DriftSummary.IntegrityDrift > 0 {
			// Find the components with integrity drift
			for _, changed := range result.Changed {
				if changed.Drift != nil && changed.Drift.Type == DriftTypeIntegrity {
					violations = append(violations, PolicyViolation{
						Rule:     "deny_integrity_drift",
						Message:  fmt.Sprintf("component %s has hash change without version change (potential supply chain attack)", changed.Name),
						Severity: SeverityError,
					})
				}
			}
		}
	}

	// Check max depth (NEW)
	if policy.MaxDepth > 0 && result.Dependencies != nil && result.Dependencies.DepthSummary != nil {
		// Count violations at or above max depth
		var violatingDeps []string
		for _, td := range result.Dependencies.TransitiveNew {
			if td.Depth >= policy.MaxDepth {
				violatingDeps = append(violatingDeps, fmt.Sprintf("%s (depth %d)", td.Target, td.Depth))
			}
		}
		if len(violatingDeps) > 0 {
			violations = append(violations, PolicyViolation{
				Rule:     "max_depth",
				Message:  fmt.Sprintf("new transitive dependencies at depth >= %d: %v", policy.MaxDepth, violatingDeps),
				Severity: SeverityError,
			})
		}
	}

	// Warn on supplier change (NEW)
	if policy.WarnSupplierChange {
		for _, changed := range result.Changed {
			if changed.Before.Supplier != changed.After.Supplier &&
				(changed.Before.Supplier != "" || changed.After.Supplier != "") {
				violations = append(violations, PolicyViolation{
					Rule:     "warn_supplier_change",
					Message:  fmt.Sprintf("component %s supplier changed: %q -> %q", changed.Name, changed.Before.Supplier, changed.After.Supplier),
					Severity: SeverityWarning,
				})
			}
		}
	}

	// Warn on new transitive deps (NEW)
	if policy.WarnNewTransitive && result.Dependencies != nil {
		if len(result.Dependencies.TransitiveNew) > 0 {
			violations = append(violations, PolicyViolation{
				Rule:     "warn_new_transitive",
				Message:  fmt.Sprintf("found %d new transitive dependencies", len(result.Dependencies.TransitiveNew)),
				Severity: SeverityWarning,
			})
		}
	}

	return violations
}

// HasErrors returns true if any violation is an error (not warning)
func HasErrors(violations []PolicyViolation) bool {
	for _, v := range violations {
		if v.Severity == SeverityError {
			return true
		}
	}
	return false
}
