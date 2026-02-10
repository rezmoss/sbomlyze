package sbom

import "testing"

func TestCompareComponents_NoChanges(t *testing.T) {
	c := Component{
		Version:  "1.0.0",
		Licenses: []string{"MIT"},
		Hashes:   map[string]string{"SHA256": "abc"},
	}
	changes := CompareComponents(c, c)
	if len(changes) != 0 {
		t.Errorf("expected no changes, got %v", changes)
	}
}

func TestCompareComponents_VersionChange(t *testing.T) {
	before := Component{Version: "1.0.0"}
	after := Component{Version: "2.0.0"}
	changes := CompareComponents(before, after)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}
	if changes[0] != "version: 1.0.0 -> 2.0.0" {
		t.Errorf("unexpected change: %s", changes[0])
	}
}

func TestCompareComponents_LicenseChange(t *testing.T) {
	before := Component{Licenses: []string{"MIT"}}
	after := Component{Licenses: []string{"Apache-2.0"}}
	changes := CompareComponents(before, after)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}
	if changes[0] != "licenses: [MIT] -> [Apache-2.0]" {
		t.Errorf("unexpected change: %s", changes[0])
	}
}

func TestCompareComponents_HashChange(t *testing.T) {
	before := Component{Hashes: map[string]string{"SHA256": "abc"}}
	after := Component{Hashes: map[string]string{"SHA256": "xyz"}}
	changes := CompareComponents(before, after)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}
	if changes[0] != "hash[SHA256]: abc -> xyz" {
		t.Errorf("unexpected change: %s", changes[0])
	}
}

func TestCompareComponents_MultipleChanges(t *testing.T) {
	before := Component{
		Version:  "1.0.0",
		Licenses: []string{"MIT"},
		Hashes:   map[string]string{"SHA256": "abc"},
	}
	after := Component{
		Version:  "2.0.0",
		Licenses: []string{"Apache-2.0"},
		Hashes:   map[string]string{"SHA256": "xyz"},
	}
	changes := CompareComponents(before, after)
	if len(changes) != 3 {
		t.Errorf("expected 3 changes, got %d: %v", len(changes), changes)
	}
}

func TestCompareComponents_HashAdded(t *testing.T) {
	before := Component{Hashes: map[string]string{"SHA256": "abc"}}
	after := Component{Hashes: map[string]string{"SHA256": "abc", "SHA1": "def"}}
	changes := CompareComponents(before, after)
	// Added hash in after should NOT be flagged as a change
	if len(changes) != 0 {
		t.Errorf("expected no changes for added hash, got %v", changes)
	}
}

