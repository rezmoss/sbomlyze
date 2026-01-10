package identity

import "testing"

func TestComponentIdentity(t *testing.T) {
	t.Run("matches by PURL first", func(t *testing.T) {
		c1 := ComponentIdentity{
			Name: "different-name",
			PURL: "pkg:npm/lodash@4.17.21",
			CPEs: []string{"cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"},
		}
		c2 := ComponentIdentity{
			Name: "lodash",
			PURL: "pkg:npm/lodash@4.17.20", // different version, same base
			CPEs: []string{"cpe:2.3:a:other:other:1.0.0:*:*:*:*:*:*:*"},
		}

		id1 := ComputeID(c1)
		id2 := ComputeID(c2)

		if id1 != id2 {
			t.Errorf("PURL should match: %s != %s", id1, id2)
		}
	})

	t.Run("falls back to CPE when no PURL", func(t *testing.T) {
		c1 := ComponentIdentity{
			Name: "different-name",
			CPEs: []string{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
		}
		c2 := ComponentIdentity{
			Name: "product",
			CPEs: []string{"cpe:2.3:a:vendor:product:2.0.0:*:*:*:*:*:*:*"},
		}

		id1 := ComputeID(c1)
		id2 := ComputeID(c2)

		if id1 != id2 {
			t.Errorf("CPE should match (same vendor:product): %s != %s", id1, id2)
		}
	})

	t.Run("falls back to BOMRef when no PURL or CPE", func(t *testing.T) {
		c1 := ComponentIdentity{
			Name:   "my-component",
			BOMRef: "component-123",
		}
		c2 := ComponentIdentity{
			Name:   "renamed-component",
			BOMRef: "component-123",
		}

		id1 := ComputeID(c1)
		id2 := ComputeID(c2)

		if id1 != id2 {
			t.Errorf("BOMRef should match: %s != %s", id1, id2)
		}
	})

	t.Run("falls back to name+namespace when no other identifiers", func(t *testing.T) {
		c1 := ComponentIdentity{
			Name:      "mypackage",
			Namespace: "com.example",
		}
		c2 := ComponentIdentity{
			Name:      "mypackage",
			Namespace: "com.example",
		}

		id1 := ComputeID(c1)
		id2 := ComputeID(c2)

		if id1 != id2 {
			t.Errorf("name+namespace should match: %s != %s", id1, id2)
		}
	})

	t.Run("different namespaces do not match", func(t *testing.T) {
		c1 := ComponentIdentity{
			Name:      "mypackage",
			Namespace: "com.example",
		}
		c2 := ComponentIdentity{
			Name:      "mypackage",
			Namespace: "org.other",
		}

		id1 := ComputeID(c1)
		id2 := ComputeID(c2)

		if id1 == id2 {
			t.Errorf("different namespaces should not match: %s == %s", id1, id2)
		}
	})

	t.Run("falls back to name only as last resort", func(t *testing.T) {
		c1 := ComponentIdentity{Name: "simple-package"}
		c2 := ComponentIdentity{Name: "simple-package"}

		id1 := ComputeID(c1)
		id2 := ComputeID(c2)

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
			result := NormalizeCPE(tt.cpe)
			if result != tt.expected {
				t.Errorf("NormalizeCPE(%q) = %q, want %q", tt.cpe, result, tt.expected)
			}
		})
	}
}

func TestIdentityPrecedence(t *testing.T) {
	t.Run("PURL takes precedence over CPE", func(t *testing.T) {
		c := ComponentIdentity{
			Name: "test",
			PURL: "pkg:npm/test@1.0.0",
			CPEs: []string{"cpe:2.3:a:vendor:different:1.0.0:*:*:*:*:*:*:*"},
		}

		id := ComputeID(c)

		if id != "pkg:npm/test" {
			t.Errorf("expected PURL-based ID, got %s", id)
		}
	})

	t.Run("CPE takes precedence over BOMRef", func(t *testing.T) {
		c := ComponentIdentity{
			Name:   "test",
			CPEs:   []string{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
			BOMRef: "ref-123",
		}

		id := ComputeID(c)

		if id != "cpe:vendor:product" {
			t.Errorf("expected CPE-based ID, got %s", id)
		}
	})

	t.Run("BOMRef takes precedence over name", func(t *testing.T) {
		c := ComponentIdentity{
			Name:   "test",
			BOMRef: "unique-ref-456",
		}

		id := ComputeID(c)

		if id != "ref:unique-ref-456" {
			t.Errorf("expected BOMRef-based ID, got %s", id)
		}
	})
}

func TestComponentIDWithSPDXID(t *testing.T) {
	t.Run("uses SPDXID when available", func(t *testing.T) {
		c := ComponentIdentity{
			Name:   "test",
			SPDXID: "SPDXRef-Package-test",
		}

		id := ComputeID(c)

		// SPDXID should be treated like BOMRef
		if id != "ref:SPDXRef-Package-test" {
			t.Errorf("expected SPDXID-based ID, got %s", id)
		}
	})
}

func TestNormalizePURL(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		expected string
	}{
		{
			"strips version",
			"pkg:npm/lodash@4.17.21",
			"pkg:npm/lodash",
		},
		{
			"strips qualifiers",
			"pkg:npm/lodash@4.17.21?vcs_url=git://github.com",
			"pkg:npm/lodash",
		},
		{
			"strips subpath",
			"pkg:npm/lodash@4.17.21#lib/index.js",
			"pkg:npm/lodash",
		},
		{
			"handles PURL without version",
			"pkg:npm/lodash",
			"pkg:npm/lodash",
		},
		{
			"handles empty string",
			"",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePURL(tt.purl)
			if result != tt.expected {
				t.Errorf("NormalizePURL(%q) = %q, want %q", tt.purl, result, tt.expected)
			}
		})
	}
}

func TestExtractPURLVersion(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		expected string
	}{
		{
			"extracts version",
			"pkg:npm/lodash@4.17.21",
			"4.17.21",
		},
		{
			"extracts version with qualifiers",
			"pkg:npm/lodash@4.17.21?vcs_url=git://github.com",
			"4.17.21",
		},
		{
			"extracts version with subpath",
			"pkg:npm/lodash@4.17.21#lib/index.js",
			"4.17.21",
		},
		{
			"returns empty for PURL without version",
			"pkg:npm/lodash",
			"",
		},
		{
			"handles empty string",
			"",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractPURLVersion(tt.purl)
			if result != tt.expected {
				t.Errorf("ExtractPURLVersion(%q) = %q, want %q", tt.purl, result, tt.expected)
			}
		})
	}
}
