package main

import (
	"testing"
)

func TestClassifyDrift(t *testing.T) {
	t.Run("version drift when only version changes", func(t *testing.T) {
		before := Component{
			ID:      "pkg:npm/lodash",
			Name:    "lodash",
			Version: "4.17.20",
			Hashes:  map[string]string{"SHA256": "abc123"},
		}
		after := Component{
			ID:      "pkg:npm/lodash",
			Name:    "lodash",
			Version: "4.17.21",
			Hashes:  map[string]string{"SHA256": "def456"},
		}

		drift := classifyDrift(before, after)

		if drift.Type != DriftTypeVersion {
			t.Errorf("expected version drift, got %s", drift.Type)
		}
	})

	t.Run("integrity drift when hash changes without version change", func(t *testing.T) {
		before := Component{
			ID:      "pkg:npm/lodash",
			Name:    "lodash",
			Version: "4.17.20",
			Hashes:  map[string]string{"SHA256": "abc123"},
		}
		after := Component{
			ID:      "pkg:npm/lodash",
			Name:    "lodash",
			Version: "4.17.20",
			Hashes:  map[string]string{"SHA256": "def456"},
		}

		drift := classifyDrift(before, after)

		if drift.Type != DriftTypeIntegrity {
			t.Errorf("expected integrity drift, got %s", drift.Type)
		}
	})

	t.Run("metadata drift when only license changes", func(t *testing.T) {
		before := Component{
			ID:       "pkg:npm/lodash",
			Name:     "lodash",
			Version:  "4.17.20",
			Licenses: []string{"MIT"},
		}
		after := Component{
			ID:       "pkg:npm/lodash",
			Name:     "lodash",
			Version:  "4.17.20",
			Licenses: []string{"Apache-2.0"},
		}

		drift := classifyDrift(before, after)

		if drift.Type != DriftTypeMetadata {
			t.Errorf("expected metadata drift, got %s", drift.Type)
		}
	})

	t.Run("no drift when identical", func(t *testing.T) {
		comp := Component{
			ID:      "pkg:npm/lodash",
			Name:    "lodash",
			Version: "4.17.20",
			Hashes:  map[string]string{"SHA256": "abc123"},
		}

		drift := classifyDrift(comp, comp)

		if drift.Type != DriftTypeNone {
			t.Errorf("expected no drift, got %s", drift.Type)
		}
	})

	t.Run("multiple drift types reports most severe", func(t *testing.T) {
		before := Component{
			ID:       "pkg:npm/lodash",
			Name:     "lodash",
			Version:  "4.17.20",
			Hashes:   map[string]string{"SHA256": "abc123"},
			Licenses: []string{"MIT"},
		}
		after := Component{
			ID:       "pkg:npm/lodash",
			Name:     "lodash",
			Version:  "4.17.20",
			Hashes:   map[string]string{"SHA256": "def456"}, // integrity change
			Licenses: []string{"Apache-2.0"},                // metadata change
		}

		drift := classifyDrift(before, after)

		// Integrity drift is more severe than metadata drift
		if drift.Type != DriftTypeIntegrity {
			t.Errorf("expected integrity drift (most severe), got %s", drift.Type)
		}
	})
}

func TestHashDiff(t *testing.T) {
	t.Run("detects added hash", func(t *testing.T) {
		before := map[string]string{}
		after := map[string]string{"SHA256": "abc123"}

		diff := diffHashes(before, after)

		if len(diff.Added) != 1 {
			t.Errorf("expected 1 added hash, got %d", len(diff.Added))
		}
	})

	t.Run("detects removed hash", func(t *testing.T) {
		before := map[string]string{"SHA256": "abc123"}
		after := map[string]string{}

		diff := diffHashes(before, after)

		if len(diff.Removed) != 1 {
			t.Errorf("expected 1 removed hash, got %d", len(diff.Removed))
		}
	})

	t.Run("detects changed hash", func(t *testing.T) {
		before := map[string]string{"SHA256": "abc123"}
		after := map[string]string{"SHA256": "def456"}

		diff := diffHashes(before, after)

		if len(diff.Changed) != 1 {
			t.Errorf("expected 1 changed hash, got %d", len(diff.Changed))
		}
		if diff.Changed["SHA256"].Before != "abc123" || diff.Changed["SHA256"].After != "def456" {
			t.Errorf("unexpected change values: %+v", diff.Changed["SHA256"])
		}
	})

	t.Run("no changes for identical hashes", func(t *testing.T) {
		hashes := map[string]string{"SHA256": "abc123", "SHA512": "xyz789"}

		diff := diffHashes(hashes, hashes)

		if !diff.IsEmpty() {
			t.Error("expected empty diff for identical hashes")
		}
	})
}

func TestDriftSummary(t *testing.T) {
	t.Run("summarizes drift by type", func(t *testing.T) {
		changes := []ChangedComponent{
			{ID: "a", Drift: &DriftInfo{Type: DriftTypeVersion}},
			{ID: "b", Drift: &DriftInfo{Type: DriftTypeVersion}},
			{ID: "c", Drift: &DriftInfo{Type: DriftTypeIntegrity}},
			{ID: "d", Drift: &DriftInfo{Type: DriftTypeMetadata}},
		}

		summary := summarizeDrift(changes)

		if summary.VersionDrift != 2 {
			t.Errorf("expected 2 version drifts, got %d", summary.VersionDrift)
		}
		if summary.IntegrityDrift != 1 {
			t.Errorf("expected 1 integrity drift, got %d", summary.IntegrityDrift)
		}
		if summary.MetadataDrift != 1 {
			t.Errorf("expected 1 metadata drift, got %d", summary.MetadataDrift)
		}
	})
}

func TestEvidenceParsing(t *testing.T) {
	t.Run("extracts evidence from CycloneDX component", func(t *testing.T) {
		// This would test parsing of CycloneDX evidence field
		t.Skip("requires CycloneDX test fixture with evidence")
	})
}
