package analysis

import (
	"maps"
	"slices"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// File change kinds.
const (
	FileModified = "modified"
	FileAdded    = "added"
	FileRemoved  = "removed"
)

// Config status of an owned file
const (
	ConfigYes     = "true"
	ConfigNo      = "false"
	ConfigUnknown = "unknown" // format has no config flag
)

// FileRef: inventory file added or removed
type FileRef struct {
	Path   string            `json:"path"`
	Hashes map[string]string `json:"hashes,omitempty"`
	Owners []string          `json:"owners,omitempty"` // name@version of owners
}

// OwnedFileChange: one changed file of a pkg
type OwnedFileChange struct {
	Path         string            `json:"path"`
	Change       string            `json:"change"` // modified, added, removed
	Config       string            `json:"config"` // true, false, unknown
	HashesBefore map[string]string `json:"hashes_before,omitempty"`
	HashesAfter  map[string]string `json:"hashes_after,omitempty"`
}

// OwnedFileDrift: same-ver pkg whose owned files changed
type OwnedFileDrift struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Location string            `json:"location,omitempty"`
	Files    []OwnedFileChange `json:"files"`
}

// FileDelta: owned-file changes of a version change
type FileDelta struct {
	Modified   int `json:"modified"`
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Unverified int `json:"unverified"` // on both sides, no comparable hash
	Unchanged  int `json:"unchanged"`  // on both sides, equal hash
	// AllMatch: same paths, all hashes comparable and equal
	AllMatch bool `json:"all_match"`
}

// FileCoverage: what the file diff could check
type FileCoverage struct {
	FilesCompared     int `json:"files_compared"`    // same path both sides, comparable hash
	FilesUnverified   int `json:"files_unverified"`  // same path, no comparable hash
	AmbiguousPaths    int `json:"ambiguous_paths"`   // dup path (all-layers scan), not compared
	OwnedFilesAfter   int `json:"owned_files_after"` // after-side files w/ an owner
	UnownedFilesAfter int `json:"unowned_files_after"`
	ConfigUnknown     int `json:"config_unknown"` // owned files w/o config flag
}

// hashKind folds SHA-256/SHA256/sha256 to one key
func hashKind(alg string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(alg))
}

// compareHashes: same kind only; "equal", "modified", ""
func compareHashes(before, after map[string]string) string {
	b := make(map[string]string, len(before))
	for k, v := range before {
		b[hashKind(k)] = strings.ToLower(v)
	}
	shared := false
	for k, v := range after {
		if bv, ok := b[hashKind(k)]; ok {
			shared = true
			if bv != strings.ToLower(v) {
				return FileModified
			}
		}
	}
	if shared {
		return "equal"
	}
	return ""
}

// fileIndex: one side's inventory by path
type fileIndex struct {
	byPath    map[string]sbom.FileEntry
	ambiguous map[string]bool     // path listed >1 times
	owners    map[string][]string // path -> name@version
	config    map[string]string   // path -> config status
	present   bool                // SBOM had an inventory
}

func newFileIndex(files []sbom.FileEntry, comps []sbom.Component) *fileIndex {
	idx := &fileIndex{
		byPath: make(map[string]sbom.FileEntry, len(files)), ambiguous: map[string]bool{},
		owners: map[string][]string{}, config: map[string]string{}, present: len(files) > 0,
	}
	for _, f := range files {
		if _, dup := idx.byPath[f.Path]; dup {
			idx.ambiguous[f.Path] = true
		}
		idx.byPath[f.Path] = f
	}
	for _, c := range comps {
		cfg := make(map[string]bool, len(c.ConfigFiles))
		for _, p := range c.ConfigFiles {
			cfg[p] = true
		}
		for _, p := range c.OwnedFiles {
			idx.owners[p] = append(idx.owners[p], c.Name+"@"+c.Version)
			switch {
			case cfg[p]:
				idx.config[p] = ConfigYes
			case c.ConfigKnown && idx.config[p] != ConfigYes:
				idx.config[p] = ConfigNo
			case idx.config[p] == "":
				idx.config[p] = ConfigUnknown
			}
		}
	}
	for p, o := range idx.owners {
		slices.Sort(o)
		idx.owners[p] = slices.Compact(o)
	}
	return idx
}

// configStatus: prefer a known status from either side
func configStatus(b, a *fileIndex, path string) string {
	for _, s := range []string{a.config[path], b.config[path]} {
		if s == ConfigYes {
			return ConfigYes
		}
	}
	for _, s := range []string{a.config[path], b.config[path]} {
		if s == ConfigNo {
			return ConfigNo
		}
	}
	return ConfigUnknown
}

// ownedFileDelta: diff files two occurrences own
func ownedFileDelta(b, a sbom.Component, bi, ai *fileIndex) ([]OwnedFileChange, FileDelta) {
	var changes []OwnedFileChange
	var delta FileDelta
	bset := make(map[string]bool, len(b.OwnedFiles))
	for _, p := range b.OwnedFiles {
		bset[p] = true
	}
	aset := make(map[string]bool, len(a.OwnedFiles))
	for _, p := range a.OwnedFiles {
		aset[p] = true
	}
	for _, p := range slices.Sorted(maps.Keys(bset)) {
		bf := bi.byPath[p]
		if !aset[p] {
			delta.Removed++
			changes = append(changes, OwnedFileChange{Path: p, Change: FileRemoved, Config: configStatus(bi, ai, p), HashesBefore: bf.Hashes})
			continue
		}
		af := ai.byPath[p]
		if bi.ambiguous[p] || ai.ambiguous[p] {
			delta.Unverified++
			continue
		}
		switch compareHashes(bf.Hashes, af.Hashes) {
		case FileModified:
			delta.Modified++
			changes = append(changes, OwnedFileChange{Path: p, Change: FileModified, Config: configStatus(bi, ai, p), HashesBefore: bf.Hashes, HashesAfter: af.Hashes})
		case "":
			delta.Unverified++
		default:
			delta.Unchanged++
		}
	}
	for _, p := range slices.Sorted(maps.Keys(aset)) {
		if !bset[p] {
			delta.Added++
			changes = append(changes, OwnedFileChange{Path: p, Change: FileAdded, Config: configStatus(bi, ai, p), HashesAfter: ai.byPath[p].Hashes})
		}
	}
	delta.AllMatch = len(bset) > 0 && len(aset) > 0 && len(changes) == 0 && delta.Unverified == 0
	return changes, delta
}

// diffInventories: per-path file diff, w/ owners
func diffInventories(bi, ai *fileIndex, result *DiffResult, cov *FileCoverage) {
	owners := func(p string) []string {
		o := slices.Clone(ai.owners[p])
		if len(o) == 0 {
			o = slices.Clone(bi.owners[p])
		}
		return o
	}
	for _, p := range slices.Sorted(maps.Keys(bi.byPath)) {
		bf := bi.byPath[p]
		af, ok := ai.byPath[p]
		if !ok {
			result.FilesRemoved = append(result.FilesRemoved, FileRef{Path: p, Hashes: bf.Hashes, Owners: bi.owners[p]})
			continue
		}
		if bi.ambiguous[p] || ai.ambiguous[p] {
			cov.AmbiguousPaths++
			continue
		}
		switch compareHashes(bf.Hashes, af.Hashes) {
		case FileModified:
			cov.FilesCompared++
			result.FileChanges = append(result.FileChanges, FileChange{Path: p, HashesBefore: bf.Hashes, HashesAfter: af.Hashes, Owners: owners(p)})
		case "equal":
			cov.FilesCompared++
		default:
			cov.FilesUnverified++
		}
	}
	for _, p := range slices.Sorted(maps.Keys(ai.byPath)) {
		if _, ok := bi.byPath[p]; !ok {
			af := ai.byPath[p]
			result.FilesAdded = append(result.FilesAdded, FileRef{Path: p, Hashes: af.Hashes, Owners: ai.owners[p]})
		}
	}
	for p := range ai.byPath {
		if len(ai.owners[p]) > 0 {
			cov.OwnedFilesAfter++
			if ai.config[p] == ConfigUnknown {
				cov.ConfigUnknown++
			}
		} else {
			cov.UnownedFilesAfter++
		}
	}
}

// GatedFiles: changes to gate; config skipped unless includeConfig
func (d OwnedFileDrift) GatedFiles(includeConfig bool) []OwnedFileChange {
	var out []OwnedFileChange
	for _, f := range d.Files {
		if includeConfig || f.Config != ConfigYes {
			out = append(out, f)
		}
	}
	return out
}
