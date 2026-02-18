package output

import (
	"fmt"
	"maps"
	"slices"

	"github.com/rezmoss/sbomlyze/internal/analysis"
)

// JSONPatchOp is a JSON Patch operation (RFC 6902).
type JSONPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
	From  string      `json:"from,omitempty"`
}

// GenerateJSONPatch creates a JSON Patch from a diff.
func GenerateJSONPatch(result analysis.DiffResult) []JSONPatchOp {
	var ops []JSONPatchOp

	for i, c := range result.Added {
		ops = append(ops, JSONPatchOp{
			Op:    "add",
			Path:  fmt.Sprintf("/components/%d", i),
			Value: c,
		})
	}

	for _, c := range result.Removed {
		ops = append(ops, JSONPatchOp{
			Op:   "remove",
			Path: fmt.Sprintf("/components/%s", c.ID),
		})
	}

	for _, c := range result.Changed {
		if c.Before.Version != c.After.Version {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/version", c.ID),
				Value: c.After.Version,
			})
		}

		if !slices.Equal(c.Before.Licenses, c.After.Licenses) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/licenses", c.ID),
				Value: c.After.Licenses,
			})
		}

		if !maps.Equal(c.Before.Hashes, c.After.Hashes) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/hashes", c.ID),
				Value: c.After.Hashes,
			})
		}
	}

	return ops
}
