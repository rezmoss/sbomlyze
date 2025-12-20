package main

// DriftType classifies the type of change detected
type DriftType string

const (
	DriftTypeNone      DriftType = "none"
	DriftTypeVersion   DriftType = "version"
	DriftTypeIntegrity DriftType = "integrity"
	DriftTypeMetadata  DriftType = "metadata"
)

// DriftInfo contains details about component drift
type DriftInfo struct {
	Type         DriftType `json:"type"`
	HashChanges  *HashDiff `json:"hash_changes,omitempty"`
	VersionFrom  string    `json:"version_from,omitempty"`
	VersionTo    string    `json:"version_to,omitempty"`
	LicensesDiff []string  `json:"licenses_diff,omitempty"`
}

// HashDiff represents changes in hash values
type HashDiff struct {
	Added   map[string]string     `json:"added,omitempty"`
	Removed map[string]string     `json:"removed,omitempty"`
	Changed map[string]HashChange `json:"changed,omitempty"`
}

// HashChange represents a before/after hash value
type HashChange struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

// DriftSummary provides aggregate drift statistics
type DriftSummary struct {
	VersionDrift   int `json:"version_drift"`
	IntegrityDrift int `json:"integrity_drift"`
	MetadataDrift  int `json:"metadata_drift"`
}

// IsEmpty returns true if no hash changes
func (h *HashDiff) IsEmpty() bool {
	return len(h.Added) == 0 && len(h.Removed) == 0 && len(h.Changed) == 0
}

// classifyDrift determines the type of drift between two components
// Priority: integrity > version > metadata > none
func classifyDrift(before, after Component) DriftInfo {
	drift := DriftInfo{Type: DriftTypeNone}

	// Check for version change
	versionChanged := before.Version != after.Version
	if versionChanged {
		drift.VersionFrom = before.Version
		drift.VersionTo = after.Version
	}

	// Check for hash changes
	hashDiff := diffHashes(before.Hashes, after.Hashes)
	if !hashDiff.IsEmpty() {
		drift.HashChanges = &hashDiff
	}

	// Check for license changes
	if !equalSlices(before.Licenses, after.Licenses) {
		// Compute license diff
		beforeSet := toSet(before.Licenses)
		afterSet := toSet(after.Licenses)
		for lic := range afterSet {
			if !beforeSet[lic] {
				drift.LicensesDiff = append(drift.LicensesDiff, "+"+lic)
			}
		}
		for lic := range beforeSet {
			if !afterSet[lic] {
				drift.LicensesDiff = append(drift.LicensesDiff, "-"+lic)
			}
		}
	}

	// Classify drift type by severity
	// Integrity drift: hash changed WITHOUT version change (suspicious!)
	if !hashDiff.IsEmpty() && !versionChanged {
		drift.Type = DriftTypeIntegrity
		return drift
	}

	// Version drift: version changed (normal update)
	if versionChanged {
		drift.Type = DriftTypeVersion
		return drift
	}

	// Metadata drift: only metadata (licenses, etc.) changed
	if len(drift.LicensesDiff) > 0 {
		drift.Type = DriftTypeMetadata
		return drift
	}

	return drift
}

// diffHashes compares two hash maps
func diffHashes(before, after map[string]string) HashDiff {
	diff := HashDiff{
		Added:   make(map[string]string),
		Removed: make(map[string]string),
		Changed: make(map[string]HashChange),
	}

	// Find added and changed
	for algo, hash := range after {
		if beforeHash, exists := before[algo]; exists {
			if beforeHash != hash {
				diff.Changed[algo] = HashChange{Before: beforeHash, After: hash}
			}
		} else {
			diff.Added[algo] = hash
		}
	}

	// Find removed
	for algo, hash := range before {
		if _, exists := after[algo]; !exists {
			diff.Removed[algo] = hash
		}
	}

	return diff
}

// summarizeDrift aggregates drift statistics from changes
func summarizeDrift(changes []ChangedComponent) DriftSummary {
	summary := DriftSummary{}

	for _, c := range changes {
		if c.Drift == nil {
			continue
		}
		switch c.Drift.Type {
		case DriftTypeVersion:
			summary.VersionDrift++
		case DriftTypeIntegrity:
			summary.IntegrityDrift++
		case DriftTypeMetadata:
			summary.MetadataDrift++
		}
	}

	return summary
}
