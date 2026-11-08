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
	Type         DriftType  `json:"type"`
	HashChanges  *HashDiff  `json:"hash_changes,omitempty"`
	VersionFrom  string     `json:"version_from,omitempty"`
	VersionTo    string     `json:"version_to,omitempty"`
	Direction    string     `json:"direction,omitempty"` // upgrade|downgrade|none|unknown; version drift only
	Level        string     `json:"level,omitempty"`     // major|minor|patch|prerelease|revision|none|unknown
	Files        *FileDelta `json:"files,omitempty"`     // owned-file changes, if ownership recorded
	LicensesDiff []string   `json:"licenses_diff,omitempty"`
}

// HashDiff: digest changes by kind
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

// DriftSummary: drift counts, per occurrence
type DriftSummary struct {
	VersionDrift int `json:"version_drift"`
	// same-version, same-location pkg digest change; no files
	IntegrityDrift         int `json:"integrity_drift"`
	MetadataDrift          int `json:"metadata_drift"`
	Upgrades               int `json:"upgrades"`
	Downgrades             int `json:"downgrades"`
	UnknownDirection       int `json:"unknown_direction"`
	DistinctVersionChanges int `json:"distinct_version_changes"` // identity + from + to
	FileChanges            int `json:"file_changes"`
	LicenseChanges         int `json:"license_changes"`
	// same-ver pkgs w/ changed owned files; distinct files
	OwnedFileDrift    int `json:"owned_file_drift"`
	OwnedFilesChanged int `json:"owned_files_changed"`
}

// ChangedComponent: changed pkg occurrence, before/after
type ChangedComponent struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Location string         `json:"location,omitempty"`
	Before   sbom.Component `json:"before"`
	After    sbom.Component `json:"after"`
	Changes  []string       `json:"changes"`
	Drift    *DriftInfo     `json:"drift,omitempty"`
}

// MovedComponent: same version, other location
type MovedComponent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// FileChange: file entry w/ changed content
type FileChange struct {
	Path         string            `json:"path"`
	HashesBefore map[string]string `json:"hashes_before,omitempty"`
	HashesAfter  map[string]string `json:"hashes_after,omitempty"`
	Owners       []string          `json:"owners,omitempty"` // name@version of owners, if known
}

// VersionSetChange: versions changed at one loc, unpaired
type VersionSetChange struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Location        string   `json:"location,omitempty"`
	RemovedVersions []string `json:"removed_versions"`
	AddedVersions   []string `json:"added_versions"`
}

// DigestCoverage: same-ver pairs checkable for integrity
type DigestCoverage struct {
	SameVersionPairs int            `json:"same_version_pairs"` // same id, non-empty ver, same loc
	Comparable       int            `json:"comparable"`         // share >=1 digest kind
	BeforeOnly       int            `json:"before_only"`        // digests only before
	AfterOnly        int            `json:"after_only"`         // digests only after
	DisjointKinds    int            `json:"disjoint_kinds"`     // both have digests, no common kind
	ByKind           map[string]int `json:"by_kind"`            // comparable pairs per kind
	PackagesTotal    int            `json:"packages_total"`     // pkg occurrences in after SBOM
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
	FilesAdded        []FileRef              `json:"files_added,omitempty"`
	FilesRemoved      []FileRef              `json:"files_removed,omitempty"`
	OwnedFileDrift    []OwnedFileDrift       `json:"owned_file_drift,omitempty"`
	SourceChange      *SourceChange          `json:"source_change,omitempty"`
	Duplicates        *DuplicateReport       `json:"duplicates,omitempty"`
	Dependencies      *DependencyDiff        `json:"dependencies,omitempty"`
	DriftSummary      *DriftSummary          `json:"drift_summary,omitempty"`
	DigestCoverage    *DigestCoverage        `json:"digest_coverage,omitempty"`
	FileCoverage      *FileCoverage          `json:"file_coverage,omitempty"`
	AddedByType       []PackageSamplesByType `json:"added_by_type,omitempty"`
	RemovedByType     []PackageSamplesByType `json:"removed_by_type,omitempty"`

	// SharedPackages: pkgs on both sides (incl. moved)
	SharedPackages int `json:"-"`
}

// HasChanges: any diff that fails a change gate
func (r DiffResult) HasChanges() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0 || len(r.Changed) > 0 ||
		len(r.Moved) > 0 || len(r.FileChanges) > 0 || len(r.FilesAdded) > 0 ||
		len(r.FilesRemoved) > 0 || len(r.OwnedFileDrift) > 0 || r.SourceChange != nil
}

// SourceChange: scanned image/source version or digest changed
type SourceChange struct {
	Name string `json:"name,omitempty"`
	From string `json:"from"`
	To   string `json:"to"`
}

// SourceChangeOf: nil unless both versions known and differ
func SourceChangeOf(before, after sbom.SBOMInfo) *SourceChange {
	if before.SourceVersion == "" || after.SourceVersion == "" || before.SourceVersion == after.SourceVersion {
		return nil
	}
	return &SourceChange{Name: after.SourceName, From: before.SourceVersion, To: after.SourceVersion}
}

func (h *HashDiff) IsEmpty() bool {
	return len(h.Added) == 0 && len(h.Removed) == 0 && len(h.Changed) == 0
}

// ClassifyDrift: integrity > version > metadata > none
func ClassifyDrift(before, after sbom.Component) DriftInfo {
	drift := DriftInfo{Type: DriftTypeNone}

	versionChanged := before.Version != after.Version
	if versionChanged {
		drift.VersionFrom = before.Version
		drift.VersionTo = after.Version
		eco := Ecosystem(after)
		if eco == "unknown" {
			eco = Ecosystem(before)
		}
		drift.Direction, drift.Level = ClassifyVersionChange(eco, before.Version, after.Version)
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

// SummarizeDrift aggregates drift counts
func SummarizeDrift(changes []ChangedComponent) DriftSummary {
	summary := DriftSummary{}
	distinct := make(map[string]bool)

	for _, c := range changes {
		// OS release change is reported as an OS change
		if c.Drift == nil || c.Before.IsEvidence() {
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

// DiffComponents: DiffSBOMs w/o file inventories
func DiffComponents(before, after []sbom.Component) DiffResult {
	return DiffSBOMs(before, after, nil, nil)
}

// DiffSBOMs: occurrence + file diff, order-independent
func DiffSBOMs(before, after []sbom.Component, beforeFiles, afterFiles []sbom.FileEntry) DiffResult {
	beforeDups := DetectDuplicates(before)
	afterDups := DetectDuplicates(after)

	var result DiffResult

	beforePkgs, beforeFileComps := splitFiles(before)
	afterPkgs, afterFileComps := splitFiles(after)
	bi, ai := newFileIndex(beforeFiles, beforePkgs), newFileIndex(afterFiles, afterPkgs)
	var cov FileCoverage
	matchPackages(beforePkgs, afterPkgs, bi, ai, &result)
	matchFiles(beforeFileComps, afterFileComps, &result, &cov)
	if bi.present || ai.present {
		diffInventories(bi, ai, &result, &cov)
	}
	if bi.present || ai.present || len(beforeFileComps)+len(afterFileComps) > 0 {
		result.FileCoverage = &cov
	}
	sortResult(&result)

	summary := SummarizeDrift(result.Changed)
	summary.FileChanges = len(result.FileChanges)
	summary.OwnedFileDrift = len(result.OwnedFileDrift)
	changedFiles := map[string]bool{}
	for _, d := range result.OwnedFileDrift {
		for _, f := range d.Files {
			changedFiles[f.Path] = true
		}
	}
	summary.OwnedFilesChanged = len(changedFiles)
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
