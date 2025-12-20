package main

import "testing"

func TestComponentIdentity(t *testing.T) {
	t.Run("matches by PURL first", func(t *testing.T) {
		c1 := Component{
			Name:    "different-name",
			Version: "1.0.0",
			PURL:    "pkg:npm/lodash@4.17.21",
			CPEs:    []string{"cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"},
		}
		c2 := Component{
			Name:    "lodash",
			Version: "4.17.21",
			PURL:    "pkg:npm/lodash@4.17.20", // different version, same base
			CPEs:    []string{"cpe:2.3:a:other:other:1.0.0:*:*:*:*:*:*:*"},
		}

		id1 := computeComponentID(c1)
		id2 := computeComponentID(c2)

		if id1 != id2 {
			t.Errorf("PURL should match: %s != %s", id1, id2)
		}
	})

	t.Run("falls back to CPE when no PURL", func(t *testing.T) {
		c1 := Component{
			Name:    "different-name",
			Version: "1.0.0",
			CPEs:    []string{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
		}
		c2 := Component{
			Name:    "product",
			Version: "2.0.0",
			CPEs:    []string{"cpe:2.3:a:vendor:product:2.0.0:*:*:*:*:*:*:*"},
		}

		id1 := computeComponentID(c1)
		id2 := computeComponentID(c2)

		if id1 != id2 {
			t.Errorf("CPE should match (same vendor:product): %s != %s", id1, id2)
		}
	})

	t.Run("falls back to BOMRef when no PURL or CPE", func(t *testing.T) {
		c1 := Component{
			Name:    "my-component",
			Version: "1.0.0",
			BOMRef:  "component-123",
		}
		c2 := Component{
			Name:    "renamed-component",
			Version: "1.0.0",
			BOMRef:  "component-123",
		}

		id1 := computeComponentID(c1)
		id2 := computeComponentID(c2)

		if id1 != id2 {
			t.Errorf("BOMRef should match: %s != %s", id1, id2)
		}
	})

	t.Run("falls back to name+namespace when no other identifiers", func(t *testing.T) {
		c1 := Component{
			Name:      "mypackage",
			Namespace: "com.example",
			Version:   "1.0.0",
		}
		c2 := Component{
			Name:      "mypackage",
			Namespace: "com.example",
			Version:   "2.0.0",
		}

		id1 := computeComponentID(c1)
		id2 := computeComponentID(c2)

		if id1 != id2 {
			t.Errorf("name+namespace should match: %s != %s", id1, id2)
		}
	})

	t.Run("different namespaces do not match", func(t *testing.T) {
		c1 := Component{
			Name:      "mypackage",
			Namespace: "com.example",
		}
		c2 := Component{
			Name:      "mypackage",
			Namespace: "org.other",
		}

		id1 := computeComponentID(c1)
		id2 := computeComponentID(c2)

		if id1 == id2 {
			t.Errorf("different namespaces should not match: %s == %s", id1, id2)
		}
	})

	t.Run("falls back to name only as last resort", func(t *testing.T) {
		c1 := Component{Name: "simple-package"}
		c2 := Component{Name: "simple-package"}

		id1 := computeComponentID(c1)
		id2 := computeComponentID(c2)

		if id1 != id2 {
			t.Errorf("name should match: %s != %s", id1, id2)
		}
	})
}

func TestNormalizeCPE(t *testing.T) {
	tests := []struct {
		name     string
		cpe      string
		expected string
	}{
		{
			"extracts vendor:product from CPE 2.3",
			"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
			"cpe:apache:log4j",
		},
		{
			"extracts vendor:product from CPE 2.2",
			"cpe:/a:apache:struts:2.5.10",
			"cpe:apache:struts",
		},
		{
			"handles CPE with special chars",
			"cpe:2.3:a:some-vendor:some-product:1.0:*:*:*:*:*:*:*",
			"cpe:some-vendor:some-product",
		},
		{
			"returns empty for invalid CPE",
			"not-a-cpe",
			"",
		},
		{
			"returns empty for empty string",
			"",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeCPE(tt.cpe)
			if result != tt.expected {
				t.Errorf("normalizeCPE(%q) = %q, want %q", tt.cpe, result, tt.expected)
			}
		})
	}
}

func TestIdentityPrecedence(t *testing.T) {
	t.Run("PURL takes precedence over CPE", func(t *testing.T) {
		c := Component{
			Name: "test",
			PURL: "pkg:npm/test@1.0.0",
			CPEs: []string{"cpe:2.3:a:vendor:different:1.0.0:*:*:*:*:*:*:*"},
		}

		id := computeComponentID(c)

		if id != "pkg:npm/test" {
			t.Errorf("expected PURL-based ID, got %s", id)
		}
	})

	t.Run("CPE takes precedence over BOMRef", func(t *testing.T) {
		c := Component{
			Name:   "test",
			CPEs:   []string{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
			BOMRef: "ref-123",
		}

		id := computeComponentID(c)

		if id != "cpe:vendor:product" {
			t.Errorf("expected CPE-based ID, got %s", id)
		}
	})

	t.Run("BOMRef takes precedence over name", func(t *testing.T) {
		c := Component{
			Name:   "test",
			BOMRef: "unique-ref-456",
		}

		id := computeComponentID(c)

		if id != "ref:unique-ref-456" {
			t.Errorf("expected BOMRef-based ID, got %s", id)
		}
	})
}

func TestComponentIDWithSPDXID(t *testing.T) {
	t.Run("uses SPDXID when available", func(t *testing.T) {
		c := Component{
			Name:   "test",
			SPDXID: "SPDXRef-Package-test",
		}

		id := computeComponentID(c)

		// SPDXID should be treated like BOMRef
		if id != "ref:SPDXRef-Package-test" {
			t.Errorf("expected SPDXID-based ID, got %s", id)
		}
	})
}
