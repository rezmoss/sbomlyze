package analysis

import (
	"maps"
	"slices"
	"sort"

	"github.com/rezmoss/sbomlyze/internal/identity"
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
	Direction    string    `json:"direction,omitempty"` // upgrade, downgrade, none, unknown (version drift only)
	Level        string    `json:"level,omitempty"`     // major, minor, patch, prerelease, none, unknown (version drift only)
	LicensesDiff []string  `json:"licenses_diff,omitempty"`
}

// HashDiff tracks digest changes, keyed by digest kind.
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

// DriftSummary aggregates drift counts. Counts are per occurrence (a package
// at one location) unless noted.
type DriftSummary struct {
	VersionDrift int `json:"version_drift"`
	// IntegrityDrift counts packages whose digest of one kind changed at the
	// same non-empty version and location. File entries never count.
	IntegrityDrift         int `json:"integrity_drift"`
	MetadataDrift          int `json:"metadata_drift"`
	Upgrades               int `json:"upgrades"`
	Downgrades             int `json:"downgrades"`
	UnknownDirection       int `json:"unknown_direction"`
	DistinctVersionChanges int `json:"distinct_version_changes"` // identity + from + to
	FileChanges            int `json:"file_changes"`
	LicenseChanges         int `json:"license_changes"`
}

// ChangedComponent holds a changed package occurrence with before/after state.
type ChangedComponent struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Location string         `json:"location,omitempty"`
	Before   sbom.Component `json:"before"`
	After    sbom.Component `json:"after"`
	Changes  []string       `json:"changes"`
	Drift    *DriftInfo     `json:"drift,omitempty"`
}

// MovedComponent is a package at the same version found at a different location.
type MovedComponent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// FileChange is a file entry (scanner evidence, not a package) whose content changed.
type FileChange struct {
	Path         string            `json:"path"`
	HashesBefore map[string]string `json:"hashes_before,omitempty"`
	HashesAfter  map[string]string `json:"hashes_after,omitempty"`
}

// VersionSetChange records several versions of one package changing at one
// location, where no single pairing is justified. The occurrences are also
// listed in Added and Removed.
type VersionSetChange struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Location        string   `json:"location,omitempty"`
	RemovedVersions []string `json:"removed_versions"`
	AddedVersions   []string `json:"added_versions"`
}

// DigestCoverage describes how many same-version package pairs could be
// checked for integrity drift.
type DigestCoverage struct {
	SameVersionPairs int            `json:"same_version_pairs"` // same identity, non-empty version and location
	Comparable       int            `json:"comparable"`         // pairs sharing at least one digest kind
	BeforeOnly       int            `json:"before_only"`        // digests only before
	AfterOnly        int            `json:"after_only"`         // digests only after
	DisjointKinds    int            `json:"disjoint_kinds"`     // digests on both sides, no kind in common
	ByKind           map[string]int `json:"by_kind"`            // comparable pairs per digest kind
	PackagesTotal    int            `json:"packages_total"`     // package occurrences in the after SBOM
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
	Added             []sbom.Component       `json:"added,omitempty"`
	Removed           []sbom.Component       `json:"removed,omitempty"`
	Changed           []ChangedComponent     `json:"changed,omitempty"`
	Moved             []MovedComponent       `json:"moved,omitempty"`
	VersionSetChanges []VersionSetChange     `json:"version_set_changes,omitempty"`
	FileChanges       []FileChange           `json:"file_changes,omitempty"`
	Duplicates        *DuplicateReport       `json:"duplicates,omitempty"`
	Dependencies      *DependencyDiff        `json:"dependencies,omitempty"`
	DriftSummary      *DriftSummary          `json:"drift_summary,omitempty"`
	DigestCoverage    *DigestCoverage        `json:"digest_coverage,omitempty"`
	AddedByType       []PackageSamplesByType `json:"added_by_type,omitempty"`
	RemovedByType     []PackageSamplesByType `json:"removed_by_type,omitempty"`

	// SharedPackages counts package occurrences present on both sides
	// (unchanged, changed or moved).
	SharedPackages int `json:"-"`
}

// HasChanges reports any difference that should fail a change gate.
func (r DiffResult) HasChanges() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0 || len(r.Changed) > 0 ||
		len(r.Moved) > 0 || len(r.FileChanges) > 0
}

func (h *HashDiff) IsEmpty() bool {
	return len(h.Added) == 0 && len(h.Removed) == 0 && len(h.Changed) == 0
}

// ClassifyDrift classifies drift between two occurrences of one package at
// the same location. Priority: integrity > version > metadata > none.
// Integrity drift needs the same non-empty version and a different digest of
// the same kind; a digest present on one side only is a coverage change.
func ClassifyDrift(before, after sbom.Component) DriftInfo {
	drift := DriftInfo{Type: DriftTypeNone}

	versionChanged := before.Version != after.Version
	if versionChanged {
		drift.VersionFrom = before.Version
		drift.VersionTo = after.Version
		purl := after.PURL
		if purl == "" {
			purl = before.PURL
		}
		drift.Direction, drift.Level = ClassifyVersionChange(ExtractPURLType(purl), before.Version, after.Version)
	}

	hashDiff := DiffHashes(before.DigestSet(), after.DigestSet())
	if !hashDiff.IsEmpty() {
		drift.HashChanges = &hashDiff
	}

	drift.LicensesDiff = diffLicenses(before.Licenses, after.Licenses)

	isPackage := !before.IsEvidence() && !after.IsEvidence()
	if !versionChanged && before.Version != "" && isPackage && len(hashDiff.Changed) > 0 {
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

func diffLicenses(before, after []string) []string {
	if EqualSlices(before, after) {
		return nil
	}
	var out []string
	beforeSet := ToSet(before)
	afterSet := ToSet(after)
	for _, lic := range slices.Sorted(maps.Keys(afterSet)) {
		if !beforeSet[lic] {
			out = append(out, "+"+lic)
		}
	}
	for _, lic := range slices.Sorted(maps.Keys(beforeSet)) {
		if !afterSet[lic] {
			out = append(out, "-"+lic)
		}
	}
	return out
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

// SummarizeDrift aggregates drift counts over changed occurrences.
func SummarizeDrift(changes []ChangedComponent) DriftSummary {
	summary := DriftSummary{}
	distinct := make(map[string]bool)

	for _, c := range changes {
		if c.Drift == nil {
			continue
		}
		if len(c.Drift.LicensesDiff) > 0 {
			summary.LicenseChanges++
		}
		switch c.Drift.Type {
		case DriftTypeVersion:
			summary.VersionDrift++
			distinct[identity.MatchKey(c.ID)+"\x00"+c.Drift.VersionFrom+"\x00"+c.Drift.VersionTo] = true
			switch c.Drift.Direction {
			case DirectionUpgrade:
				summary.Upgrades++
			case DirectionDowngrade:
				summary.Downgrades++
			case DirectionUnknown:
				summary.UnknownDirection++
			}
		case DriftTypeIntegrity:
			summary.IntegrityDrift++
		case DriftTypeMetadata:
			summary.MetadataDrift++
		}
	}
	summary.DistinctVersionChanges = len(distinct)

	return summary
}

func (s DriftSummary) isEmpty() bool {
	return s == DriftSummary{}
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

// DiffComponents compares two component sets. Packages are matched as
// occurrences (identity, version, location); see matchPackages. File entries
// are compared by path and reported as FileChanges. The result does not
// depend on component order in the inputs.
func DiffComponents(before, after []sbom.Component) DiffResult {
	beforeDups := DetectDuplicates(before)
	afterDups := DetectDuplicates(after)

	var result DiffResult

	beforePkgs, beforeFiles := splitFiles(before)
	afterPkgs, afterFiles := splitFiles(after)
	matchPackages(beforePkgs, afterPkgs, &result)
	matchFiles(beforeFiles, afterFiles, &result)
	sortResult(&result)

	summary := SummarizeDrift(result.Changed)
	summary.FileChanges = len(result.FileChanges)
	if !summary.isEmpty() {
		result.DriftSummary = &summary
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
		if len(typeMap[types[i]]) != len(typeMap[types[j]]) {
			return len(typeMap[types[i]]) > len(typeMap[types[j]])
		}
		return types[i] < types[j]
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
