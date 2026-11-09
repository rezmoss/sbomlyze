package sbom

import (
	"fmt"
	"sort"
)

// CompareComponents: field changes; shared digest kinds only
func CompareComponents(before, after Component) []string {
	var changes []string
	if before.Version != after.Version {
		changes = append(changes, fmt.Sprintf("version: %s -> %s", before.Version, after.Version))
	}
	if !SameLicenses(before.Licenses, after.Licenses) {
		changes = append(changes, fmt.Sprintf("licenses: %v -> %v", before.Licenses, after.Licenses))
	}
	beforeDigests, afterDigests := before.DigestSet(), after.DigestSet()
	kinds := make([]string, 0, len(beforeDigests))
	for kind := range beforeDigests {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		hash := beforeDigests[kind]
		if newHash, exists := afterDigests[kind]; exists && hash != newHash {
			changes = append(changes, fmt.Sprintf("hash[%s]: %s -> %s", kind, hash, newHash))
		}
	}
	return changes
}
