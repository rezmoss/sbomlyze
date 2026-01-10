package output

import (
	"fmt"

	"github.com/rezmoss/sbomlyze/internal/analysis"
)

// JSONPatchOp represents a JSON Patch operation (RFC 6902)
type JSONPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
	From  string      `json:"from,omitempty"`
}

// GenerateJSONPatch creates a JSON Patch from diff results
func GenerateJSONPatch(result analysis.DiffResult) []JSONPatchOp {
	var ops []JSONPatchOp

	// Added components
	for i, c := range result.Added {
		ops = append(ops, JSONPatchOp{
			Op:    "add",
			Path:  fmt.Sprintf("/components/%d", i),
			Value: c,
		})
	}

	// Removed components
	for _, c := range result.Removed {
		ops = append(ops, JSONPatchOp{
			Op:   "remove",
			Path: fmt.Sprintf("/components/%s", c.ID),
		})
	}

	// Changed components
	for _, c := range result.Changed {
		// Version change
		if c.Before.Version != c.After.Version {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/version", c.ID),
				Value: c.After.Version,
			})
		}

		// License changes
		if !stringSliceEqual(c.Before.Licenses, c.After.Licenses) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/licenses", c.ID),
				Value: c.After.Licenses,
			})
		}

		// Hash changes
		if !hashMapEqual(c.Before.Hashes, c.After.Hashes) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/hashes", c.ID),
				Value: c.After.Hashes,
			})
		}
	}

	return ops
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hashMapEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
