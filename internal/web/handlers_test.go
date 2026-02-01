package web

import (
	"encoding/json"
	"testing"
)

func TestExtractRelationships(t *testing.T) {
	t.Run("extracts relationship counts from Syft format", func(t *testing.T) {
		data := []byte(`{
			"artifactRelationships": [
				{"type": "contains"},
				{"type": "contains"},
				{"type": "dependency-of"},
				{"type": "evident-by"}
			]
		}`)

		result := extractRelationships(data)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result["contains"] != 2 {
			t.Errorf("expected 2 contains, got %d", result["contains"])
		}
		if result["dependency-of"] != 1 {
			t.Errorf("expected 1 dependency-of, got %d", result["dependency-of"])
		}
		if result["evident-by"] != 1 {
			t.Errorf("expected 1 evident-by, got %d", result["evident-by"])
		}
	})

	t.Run("returns nil for non-Syft format", func(t *testing.T) {
		data := []byte(`{
			"bomFormat": "CycloneDX",
			"components": []
		}`)

		result := extractRelationships(data)

		if result != nil {
			t.Errorf("expected nil for non-Syft format, got %v", result)
		}
	})

	t.Run("returns nil for invalid JSON", func(t *testing.T) {
		data := []byte(`invalid json`)

		result := extractRelationships(data)

		if result != nil {
			t.Errorf("expected nil for invalid JSON, got %v", result)
		}
	})

	t.Run("returns nil for empty relationships", func(t *testing.T) {
		data := []byte(`{
			"artifactRelationships": []
		}`)

		result := extractRelationships(data)

		if result != nil {
			t.Errorf("expected nil for empty relationships, got %v", result)
		}
	})

	t.Run("handles missing type field", func(t *testing.T) {
		data := []byte(`{
			"artifactRelationships": [
				{"type": "contains"},
				{"other": "field"},
				{"type": ""}
			]
		}`)

		result := extractRelationships(data)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result["contains"] != 1 {
			t.Errorf("expected 1 contains, got %d", result["contains"])
		}
		// Empty type should not be counted
		if _, exists := result[""]; exists {
			t.Errorf("empty type should not be counted")
		}
	})
}

func TestContainsLicense(t *testing.T) {
	t.Run("finds matching license", func(t *testing.T) {
		licenses := []string{"MIT", "Apache-2.0", "GPL-3.0"}

		if !containsLicense(licenses, "mit") {
			t.Error("expected to find 'mit' in licenses")
		}
		if !containsLicense(licenses, "apache") {
			t.Error("expected to find 'apache' in licenses")
		}
	})

	t.Run("returns false for no match", func(t *testing.T) {
		licenses := []string{"MIT", "Apache-2.0"}

		if containsLicense(licenses, "gpl") {
			t.Error("expected not to find 'gpl' in licenses")
		}
	})

	t.Run("handles empty licenses", func(t *testing.T) {
		if containsLicense([]string{}, "mit") {
			t.Error("expected false for empty licenses")
		}
	})

	t.Run("case insensitive search", func(t *testing.T) {
		licenses := []string{"MIT"}

		if !containsLicense(licenses, "MIT") {
			t.Error("expected to find 'MIT'")
		}
		if !containsLicense(licenses, "mit") {
			t.Error("expected to find 'mit' (lowercase)")
		}
		if !containsLicense(licenses, "Mit") {
			t.Error("expected to find 'Mit' (mixed case)")
		}
	})
}

func TestTreeNodeJSON(t *testing.T) {
	t.Run("serializes tree node correctly", func(t *testing.T) {
		node := TreeNode{
			ID:          "pkg:npm/test@1.0.0",
			Name:        "test",
			Version:     "1.0.0",
			Type:        "npm",
			HasChildren: true,
			ChildrenIDs: []string{"child1", "child2"},
		}

		data, err := json.Marshal(node)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var decoded TreeNode
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if decoded.ID != node.ID {
			t.Errorf("ID mismatch: got %q, want %q", decoded.ID, node.ID)
		}
		if decoded.Name != node.Name {
			t.Errorf("Name mismatch: got %q, want %q", decoded.Name, node.Name)
		}
		if decoded.HasChildren != node.HasChildren {
			t.Errorf("HasChildren mismatch: got %v, want %v", decoded.HasChildren, node.HasChildren)
		}
	})
}

func TestComponentDetailJSON(t *testing.T) {
	t.Run("serializes component detail correctly", func(t *testing.T) {
		detail := ComponentDetail{
			ID:           "pkg:npm/test@1.0.0",
			Name:         "test",
			Version:      "1.0.0",
			PURL:         "pkg:npm/test@1.0.0",
			Type:         "npm",
			Licenses:     []string{"MIT"},
			Hashes:       map[string]string{"SHA256": "abc123"},
			Dependencies: []string{"dep1", "dep2"},
			Supplier:     "Test Supplier",
			RawJSON:      json.RawMessage(`{"key": "value"}`),
		}

		data, err := json.Marshal(detail)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var decoded ComponentDetail
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if decoded.ID != detail.ID {
			t.Errorf("ID mismatch: got %q, want %q", decoded.ID, detail.ID)
		}
		if decoded.Supplier != detail.Supplier {
			t.Errorf("Supplier mismatch: got %q, want %q", decoded.Supplier, detail.Supplier)
		}
		if len(decoded.Licenses) != 1 || decoded.Licenses[0] != "MIT" {
			t.Errorf("Licenses mismatch: got %v, want [MIT]", decoded.Licenses)
		}
	})

	t.Run("omits empty optional fields", func(t *testing.T) {
		detail := ComponentDetail{
			ID:   "test",
			Name: "test",
		}

		data, err := json.Marshal(detail)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		// Check that empty fields are omitted
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("failed to unmarshal to map: %v", err)
		}

		if _, exists := raw["purl"]; exists {
			t.Error("expected purl to be omitted when empty")
		}
		if _, exists := raw["licenses"]; exists {
			t.Error("expected licenses to be omitted when empty")
		}
		if _, exists := raw["supplier"]; exists {
			t.Error("expected supplier to be omitted when empty")
		}
	})
}
