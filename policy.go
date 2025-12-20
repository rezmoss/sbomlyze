package main

import (
	"encoding/json"
	"fmt"
)

type Policy struct {
	MaxAdded        int      `json:"max_added,omitempty"`
	MaxRemoved      int      `json:"max_removed,omitempty"`
	MaxChanged      int      `json:"max_changed,omitempty"`
	DenyLicenses    []string `json:"deny_licenses,omitempty"`
	RequireLicenses bool     `json:"require_licenses,omitempty"`
	DenyDuplicates  bool     `json:"deny_duplicates,omitempty"`
}

type PolicyViolation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
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
			Rule:    "max_added",
			Message: fmt.Sprintf("too many components added: %d > %d", len(result.Added), policy.MaxAdded),
		})
	}

	// Check max removed
	if policy.MaxRemoved > 0 && len(result.Removed) > policy.MaxRemoved {
		violations = append(violations, PolicyViolation{
			Rule:    "max_removed",
			Message: fmt.Sprintf("too many components removed: %d > %d", len(result.Removed), policy.MaxRemoved),
		})
	}

	// Check max changed
	if policy.MaxChanged > 0 && len(result.Changed) > policy.MaxChanged {
		violations = append(violations, PolicyViolation{
			Rule:    "max_changed",
			Message: fmt.Sprintf("too many components changed: %d > %d", len(result.Changed), policy.MaxChanged),
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
						Rule:    "deny_licenses",
						Message: fmt.Sprintf("component %s has denied license: %s", comp.Name, lic),
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
					Rule:    "require_licenses",
					Message: fmt.Sprintf("component %s has no license", comp.Name),
				})
			}
		}
	}

	// Check duplicates
	if policy.DenyDuplicates && result.Duplicates != nil {
		if len(result.Duplicates.After) > 0 {
			violations = append(violations, PolicyViolation{
				Rule:    "deny_duplicates",
				Message: fmt.Sprintf("found %d duplicate components in result", len(result.Duplicates.After)),
			})
		}
	}

	return violations
}
