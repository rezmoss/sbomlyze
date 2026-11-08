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
	ops := []JSONPatchOp{} // an empty diff is [], not null

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
		// one package in two locations is two entries
		ref := c.ID
		if c.Location != "" {
			ref += "@" + c.Location
		}
		if c.Before.Version != c.After.Version {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/version", ref),
				Value: c.After.Version,
			})
		}

		if !slices.Equal(c.Before.Licenses, c.After.Licenses) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/licenses", ref),
				Value: c.After.Licenses,
			})
		}

		if !maps.Equal(c.Before.Hashes, c.After.Hashes) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/hashes", ref),
				Value: c.After.Hashes,
			})
		}

		// go-h1 and cargo-checksum live outside Hashes
		if !maps.Equal(c.Before.Digests, c.After.Digests) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/digests", ref),
				Value: c.After.Digests,
			})
		}
	}

	for _, m := range result.Moved {
		ops = append(ops, JSONPatchOp{
			Op:   "move",
			From: fmt.Sprintf("/components/%s@%s", m.ID, m.From),
			Path: fmt.Sprintf("/components/%s@%s", m.ID, m.To),
		})
	}

	for _, f := range result.FileChanges {
		ops = append(ops, JSONPatchOp{
			Op:    "replace",
			Path:  fmt.Sprintf("/files/%s/hashes", f.Path),
			Value: f.HashesAfter,
		})
	}

	return ops
}
