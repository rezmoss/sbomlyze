package sbom

import (
	"fmt"
	"sort"
)

// CompareComponents compares two components and returns a list of changes
func CompareComponents(before, after Component) []string {
	var changes []string
	if before.Version != after.Version {
		changes = append(changes, fmt.Sprintf("version: %s -> %s", before.Version, after.Version))
	}
	if !equalSlices(before.Licenses, after.Licenses) {
		changes = append(changes, fmt.Sprintf("licenses: %v -> %v", before.Licenses, after.Licenses))
	}
	for algo, hash := range before.Hashes {
		if newHash, exists := after.Hashes[algo]; exists && hash != newHash {
			changes = append(changes, fmt.Sprintf("hash[%s]: %s -> %s", algo, hash, newHash))
		}
	}
	return changes
}

// equalSlices checks if two string slices have the same elements (order-independent)
func equalSlices(a, b []string) bool {
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
