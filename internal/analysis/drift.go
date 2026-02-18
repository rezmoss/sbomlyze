package analysis

import (
	"sort"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// DriftType classifies the kind of change.
type DriftType string

const (
	DriftTypeNone      DriftType = "none"
	DriftTypeVersion   DriftType = "version"
	DriftTypeIntegrity DriftType = "integrity"
	DriftTypeMetadata  DriftType = "metadata"
)

// DriftInfo holds drift details for a component.
type DriftInfo struct {
	Type         DriftType `json:"type"`
	HashChanges  *HashDiff `json:"hash_changes,omitempty"`
	VersionFrom  string    `json:"version_from,omitempty"`
	VersionTo    string    `json:"version_to,omitempty"`
	LicensesDiff []string  `json:"licenses_diff,omitempty"`
}

// HashDiff tracks hash changes.
type HashDiff struct {
	Added   map[string]string     `json:"added,omitempty"`
	Removed map[string]string     `json:"removed,omitempty"`
	Changed map[string]HashChange `json:"changed,omitempty"`
}

// HashChange holds before/after hash values.
type HashChange struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

// DriftSummary aggregates drift counts.
type DriftSummary struct {
	VersionDrift   int `json:"version_drift"`
	IntegrityDrift int `json:"integrity_drift"`
	MetadataDrift  int `json:"metadata_drift"`
}

// ChangedComponent holds a changed component with before/after state.
type ChangedComponent struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Before  sbom.Component `json:"before"`
	After   sbom.Component `json:"after"`
	Changes []string       `json:"changes"`
	Drift   *DriftInfo     `json:"drift,omitempty"`
}

// PackageSample is a display sample.
type PackageSample struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Type      string   `json:"type"`
	Locations []string `json:"locations,omitempty"`
}

// PackageSamplesByType groups samples by package type.
type PackageSamplesByType struct {
	Type    string          `json:"type"`
	Total   int             `json:"total"`
	Samples []PackageSample `json:"samples"`
}

// DiffResult holds the complete SBOM comparison.
type DiffResult struct {
	Added         []sbom.Component     `json:"added,omitempty"`
	Removed       []sbom.Component     `json:"removed,omitempty"`
	Changed       []ChangedComponent   `json:"changed,omitempty"`
	Duplicates    *DuplicateReport     `json:"duplicates,omitempty"`
	Dependencies  *DependencyDiff      `json:"dependencies,omitempty"`
	DriftSummary  *DriftSummary        `json:"drift_summary,omitempty"`
	AddedByType   []PackageSamplesByType `json:"added_by_type,omitempty"`
	RemovedByType []PackageSamplesByType `json:"removed_by_type,omitempty"`
}

func (h *HashDiff) IsEmpty() bool {
	return len(h.Added) == 0 && len(h.Removed) == 0 && len(h.Changed) == 0
}

// ClassifyDrift classifies drift. Priority: integrity > version > metadata > none
func ClassifyDrift(before, after sbom.Component) DriftInfo {
	drift := DriftInfo{Type: DriftTypeNone}

	versionChanged := before.Version != after.Version
	if versionChanged {
		drift.VersionFrom = before.Version
		drift.VersionTo = after.Version
	}

	hashDiff := DiffHashes(before.Hashes, after.Hashes)
	if !hashDiff.IsEmpty() {
		drift.HashChanges = &hashDiff
	}

	if !EqualSlices(before.Licenses, after.Licenses) {
		beforeSet := ToSet(before.Licenses)
		afterSet := ToSet(after.Licenses)
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

	if !hashDiff.IsEmpty() && !versionChanged {
		drift.Type = DriftTypeIntegrity
		return drift
	}

	if versionChanged {
		drift.Type = DriftTypeVersion
		return drift
	}

	if len(drift.LicensesDiff) > 0 {
		drift.Type = DriftTypeMetadata
		return drift
	}

	return drift
}

func DiffHashes(before, after map[string]string) HashDiff {
	diff := HashDiff{
		Added:   make(map[string]string),
		Removed: make(map[string]string),
		Changed: make(map[string]HashChange),
	}

	for algo, hash := range after {
		if beforeHash, exists := before[algo]; exists {
			if beforeHash != hash {
				diff.Changed[algo] = HashChange{Before: beforeHash, After: hash}
			}
		} else {
			diff.Added[algo] = hash
		}
	}

	for algo, hash := range before {
		if _, exists := after[algo]; !exists {
			diff.Removed[algo] = hash
		}
	}

	return diff
}

// SummarizeDrift aggregates drift counts.
func SummarizeDrift(changes []ChangedComponent) DriftSummary {
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

func ToSet(slice []string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range slice {
		set[s] = true
	}
	return set
}

func EqualSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

// DiffComponents compares two component sets.
func DiffComponents(before, after []sbom.Component) DiffResult {
	beforeDups := DetectDuplicates(before)
	afterDups := DetectDuplicates(after)

	beforeMap := make(map[string]sbom.Component)
	afterMap := make(map[string]sbom.Component)

	for _, c := range before {
		if _, exists := beforeMap[c.ID]; !exists {
			beforeMap[c.ID] = c
		}
	}
	for _, c := range after {
		if _, exists := afterMap[c.ID]; !exists {
			afterMap[c.ID] = c
		}
	}

	var result DiffResult

	for id, c := range afterMap {
		if _, exists := beforeMap[id]; !exists {
			result.Added = append(result.Added, c)
		}
	}

	for id, c := range beforeMap {
		if _, exists := afterMap[id]; !exists {
			result.Removed = append(result.Removed, c)
		}
	}

	for id, b := range beforeMap {
		if a, exists := afterMap[id]; exists {
			changes := sbom.CompareComponents(b, a)
			if len(changes) > 0 {
				drift := ClassifyDrift(b, a)
				result.Changed = append(result.Changed, ChangedComponent{
					ID:      id,
					Name:    b.Name,
					Before:  b,
					After:   a,
					Changes: changes,
					Drift:   &drift,
				})
			}
		}
	}

	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].ID < result.Added[j].ID })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].ID < result.Removed[j].ID })
	sort.Slice(result.Changed, func(i, j int) bool { return result.Changed[i].ID < result.Changed[j].ID })

	// Compute drift summary
	if len(result.Changed) > 0 {
		summary := SummarizeDrift(result.Changed)
		if summary.VersionDrift > 0 || summary.IntegrityDrift > 0 || summary.MetadataDrift > 0 {
			result.DriftSummary = &summary
		}
	}

	if len(beforeDups) > 0 || len(afterDups) > 0 {
		versionDiff := DiffDuplicateVersions(beforeDups, afterDups)
		result.Duplicates = &DuplicateReport{
			Before: beforeDups,
			After:  afterDups,
		}
		if !versionDiff.IsEmpty() {
			result.Duplicates.VersionDiff = &versionDiff
		}
	}

	// Detect collisions in both SBOMs
	beforeCollisions := DetectCollisions(before)
	afterCollisions := DetectCollisions(after)
	if len(beforeCollisions) > 0 || len(afterCollisions) > 0 {
		if result.Duplicates == nil {
			result.Duplicates = &DuplicateReport{}
		}
		// Combine and deduplicate collisions
		allCollisions := append(beforeCollisions, afterCollisions...)
		seen := make(map[string]bool)
		for _, c := range allCollisions {
			key := c.ID + ":" + c.Reason
			if !seen[key] {
				result.Duplicates.Collisions = append(result.Duplicates.Collisions, c)
				seen[key] = true
			}
		}
	}

	// Dependency graph diff
	beforeGraph := BuildDependencyGraph(before)
	afterGraph := BuildDependencyGraph(after)
	depDiff := DiffDependencyGraphs(beforeGraph, afterGraph)
	if !depDiff.IsEmpty() {
		result.Dependencies = &depDiff
	}

	return result
}

func groupSamplesByType(comps []sbom.Component, maxSamples int) []PackageSamplesByType {
	typeMap := make(map[string][]sbom.Component)
	for _, c := range comps {
		ptype := ExtractPURLType(c.PURL)
		if ptype == "unknown" && c.PURL == "" {
			ptype = ExtractPURLType(c.ID)
		}
		typeMap[ptype] = append(typeMap[ptype], c)
	}

	// Sort by count descending
	types := make([]string, 0, len(typeMap))
	for t := range typeMap {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		return len(typeMap[types[i]]) > len(typeMap[types[j]])
	})

	var result []PackageSamplesByType
	for _, t := range types {
		group := typeMap[t]
		samples := make([]PackageSample, 0, maxSamples)
		for i, c := range group {
			if i >= maxSamples {
				break
			}
			samples = append(samples, PackageSample{
				Name:      c.Name,
				Version:   c.Version,
				Type:      t,
				Locations: c.Locations,
			})
		}
		result = append(result, PackageSamplesByType{
			Type:    t,
			Total:   len(group),
			Samples: samples,
		})
	}
	return result
}

// ComputePackageSamples fills AddedByType and RemovedByType.
func ComputePackageSamples(result *DiffResult) {
	if len(result.Added) > 0 {
		result.AddedByType = groupSamplesByType(result.Added, 5)
	}
	if len(result.Removed) > 0 {
		result.RemovedByType = groupSamplesByType(result.Removed, 5)
	}
}
