package convert

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func sampleSyftComponents() []sbom.Component {
	return []sbom.Component{
		{
			Name:    "busybox",
			Version: "1.36.1-r15",
			PURL:    "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64",
			BOMRef:  "busybox-ref",
			Type:    "apk",
			FoundBy: "apkdb-cataloger",
			Language: "go",
			Licenses: []string{"GPL-2.0-only"},
			CPEs: []string{
				"cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*",
			},
			Locations: []string{"/lib/apk/db/installed"},
			Dependencies: []string{"dep-musl"},
			ID:           "comp-busybox",
		},
		{
			Name:    "musl",
			Version: "1.2.4-r2",
			PURL:    "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64",
			BOMRef:  "musl-ref",
			Type:    "apk",
			FoundBy: "apkdb-cataloger",
			ID:      "dep-musl",
		},
	}
}

func sampleSyftInfo() sbom.SBOMInfo {
	return sbom.SBOMInfo{
		OSName:       "alpine",
		OSVersion:    "3.18.6",
		OSPrettyName: "Alpine Linux v3.18",
		OSIDLike:     []string{"alpine"},
		SourceType:   "image",
		SourceName:   "alpine:latest",
		SourceID:     "sha256:abc123",
	}
}

func TestWriteSyft_ValidStructure(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	requiredKeys := []string{"artifacts", "artifactRelationships", "descriptor", "schema", "source", "distro", "files"}
	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("Required top-level key %q is missing", key)
		}
	}

	if _, ok := raw["artifacts"].([]interface{}); !ok {
		t.Error("artifacts is not an array")
	}

	if _, ok := raw["artifactRelationships"].([]interface{}); !ok {
		t.Error("artifactRelationships is not an array")
	}
}

func TestWriteSyft_ArtifactFields(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			PURL    string `json:"purl"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if len(doc.Artifacts) != 2 {
		t.Fatalf("Artifacts count = %d, want 2", len(doc.Artifacts))
	}

	a := doc.Artifacts[0]
	if a.ID == "" {
		t.Error("Artifact ID is empty")
	}
	if a.Name != "busybox" {
		t.Errorf("Name = %q, want %q", a.Name, "busybox")
	}
	if a.Version != "1.36.1-r15" {
		t.Errorf("Version = %q, want %q", a.Version, "1.36.1-r15")
	}
	if a.Type != "apk" {
		t.Errorf("Type = %q, want %q", a.Type, "apk")
	}
	if a.PURL != "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64" {
		t.Errorf("PURL = %q, want %q", a.PURL, "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64")
	}
}

func TestWriteSyft_ReParseRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	comps, err := sbom.ParseSyft(buf.Bytes())
	if err != nil {
		t.Fatalf("Failed to re-parse Syft output: %v", err)
	}

	if len(comps) != 2 {
		t.Errorf("Re-parsed component count = %d, want 2", len(comps))
	}

	if comps[0].Name != "busybox" {
		t.Errorf("Component name = %q, want %q", comps[0].Name, "busybox")
	}
	if comps[0].Version != "1.36.1-r15" {
		t.Errorf("Component version = %q, want %q", comps[0].Version, "1.36.1-r15")
	}
}

func TestWriteSyft_CPEs(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			CPEs []struct {
				CPE string `json:"cpe"`
			} `json:"cpes"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	a := doc.Artifacts[0]
	if len(a.CPEs) != 1 {
		t.Fatalf("CPEs count = %d, want 1", len(a.CPEs))
	}
	if a.CPEs[0].CPE != "cpe:2.3:a:busybox:busybox:1.36.1-r15:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want correct CPE string", a.CPEs[0].CPE)
	}
}

func TestWriteSyft_Licenses(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			Licenses []struct {
				Value          string `json:"value"`
				SPDXExpression string `json:"spdxExpression"`
			} `json:"licenses"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	a := doc.Artifacts[0]
	if len(a.Licenses) != 1 {
		t.Fatalf("Licenses count = %d, want 1", len(a.Licenses))
	}
	if a.Licenses[0].Value != "GPL-2.0-only" {
		t.Errorf("License value = %q, want %q", a.Licenses[0].Value, "GPL-2.0-only")
	}
	if a.Licenses[0].SPDXExpression != "GPL-2.0-only" {
		t.Errorf("License SPDXExpression = %q, want %q", a.Licenses[0].SPDXExpression, "GPL-2.0-only")
	}
}

func TestWriteSyft_Locations(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	a := doc.Artifacts[0]
	if len(a.Locations) != 1 {
		t.Fatalf("Locations count = %d, want 1", len(a.Locations))
	}
	if a.Locations[0].Path != "/lib/apk/db/installed" {
		t.Errorf("Location path = %q, want %q", a.Locations[0].Path, "/lib/apk/db/installed")
	}
}

func TestWriteSyft_Language(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			Language string `json:"language"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if doc.Artifacts[0].Language != "go" {
		t.Errorf("Language = %q, want %q", doc.Artifacts[0].Language, "go")
	}
}

func TestWriteSyft_FoundBy(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			FoundBy string `json:"foundBy"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if doc.Artifacts[0].FoundBy != "apkdb-cataloger" {
		t.Errorf("FoundBy = %q, want %q", doc.Artifacts[0].FoundBy, "apkdb-cataloger")
	}
}

func TestWriteSyft_Dependencies(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		ArtifactRelationships []struct {
			Parent string `json:"parent"`
			Child  string `json:"child"`
			Type   string `json:"type"`
		} `json:"artifactRelationships"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	found := false
	for _, rel := range doc.ArtifactRelationships {
		if rel.Type == "dependency-of" {
			found = true
			if rel.Parent == "" || rel.Child == "" {
				t.Error("Relationship has empty parent or child")
			}
		}
	}
	if !found {
		t.Error("Expected at least one dependency-of relationship")
	}
}

func TestWriteSyft_Source(t *testing.T) {
	var buf bytes.Buffer
	info := sampleSyftInfo()
	err := WriteSyft(&buf, sampleSyftComponents(), info)
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Source struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"source"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if doc.Source.ID != "sha256:abc123" {
		t.Errorf("Source ID = %q, want %q", doc.Source.ID, "sha256:abc123")
	}
	if doc.Source.Name != "alpine:latest" {
		t.Errorf("Source Name = %q, want %q", doc.Source.Name, "alpine:latest")
	}
	if doc.Source.Type != "image" {
		t.Errorf("Source Type = %q, want %q", doc.Source.Type, "image")
	}
}

func TestWriteSyft_Distro(t *testing.T) {
	var buf bytes.Buffer
	info := sampleSyftInfo()
	err := WriteSyft(&buf, sampleSyftComponents(), info)
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Distro struct {
			Name       string   `json:"name"`
			Version    string   `json:"version"`
			PrettyName string   `json:"prettyName"`
			IDLike     []string `json:"idLike"`
		} `json:"distro"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if doc.Distro.Name != "alpine" {
		t.Errorf("Distro name = %q, want %q", doc.Distro.Name, "alpine")
	}
	if doc.Distro.Version != "3.18.6" {
		t.Errorf("Distro version = %q, want %q", doc.Distro.Version, "3.18.6")
	}
	if doc.Distro.PrettyName != "Alpine Linux v3.18" {
		t.Errorf("Distro prettyName = %q, want %q", doc.Distro.PrettyName, "Alpine Linux v3.18")
	}
	if len(doc.Distro.IDLike) != 1 || doc.Distro.IDLike[0] != "alpine" {
		t.Errorf("Distro idLike = %v, want [alpine]", doc.Distro.IDLike)
	}
}

func TestWriteSyft_TypeInference(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		wantType string
	}{
		{"npm", "pkg:npm/express@4.18.0", "npm"},
		{"pypi", "pkg:pypi/requests@2.31.0", "python"},
		{"gem", "pkg:gem/rails@7.0.0", "gem"},
		{"maven", "pkg:maven/org.apache/commons@1.0", "java-archive"},
		{"golang", "pkg:golang/github.com/foo/bar@1.0", "go-module"},
		{"cargo", "pkg:cargo/serde@1.0", "rust-crate"},
		{"rpm", "pkg:rpm/fedora/kernel@5.0", "rpm"},
		{"deb", "pkg:deb/debian/libc6@2.31", "deb"},
		{"apk", "pkg:apk/alpine/musl@1.2.4", "apk"},
		{"nuget", "pkg:nuget/Newtonsoft.Json@13.0", "dotnet"},
		{"cocoapods", "pkg:cocoapods/Alamofire@5.0", "pod"},
		{"hex", "pkg:hex/phoenix@1.7", "hex"},
		{"composer", "pkg:composer/laravel/framework@10.0", "php-composer"},
		{"unknown purl", "pkg:unknown/foo@1.0", "unknown"},
		{"no purl no type", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			comps := []sbom.Component{
				{Name: "test", Version: "1.0", PURL: tt.purl},
			}
			err := WriteSyft(&buf, comps, sbom.SBOMInfo{})
			if err != nil {
				t.Fatalf("WriteSyft failed: %v", err)
			}

			var doc struct {
				Artifacts []struct {
					Type string `json:"type"`
				} `json:"artifacts"`
			}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			if doc.Artifacts[0].Type != tt.wantType {
				t.Errorf("Type = %q, want %q", doc.Artifacts[0].Type, tt.wantType)
			}
		})
	}
}

func TestWriteSyft_TypeExplicitOverridesPURL(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{Name: "test", Version: "1.0", PURL: "pkg:npm/test@1.0", Type: "custom-type"},
	}
	err := WriteSyft(&buf, comps, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			Type string `json:"type"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if doc.Artifacts[0].Type != "custom-type" {
		t.Errorf("Type = %q, want %q (explicit type should override PURL inference)", doc.Artifacts[0].Type, "custom-type")
	}
}

func TestWriteSyft_EmptyInput(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, nil, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteSyft with nil components failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	artifacts, ok := raw["artifacts"].([]interface{})
	if !ok {
		t.Fatal("artifacts is not an array")
	}
	if len(artifacts) != 0 {
		t.Errorf("Expected zero artifacts, got %d", len(artifacts))
	}

	desc, ok := raw["descriptor"].(map[string]interface{})
	if !ok {
		t.Fatal("descriptor is missing or not an object")
	}
	if desc["name"] != "sbomlyze" {
		t.Errorf("Descriptor name = %v, want sbomlyze", desc["name"])
	}

	schema, ok := raw["schema"].(map[string]interface{})
	if !ok {
		t.Fatal("schema is missing or not an object")
	}
	if schema["version"] == nil || schema["version"] == "" {
		t.Error("Schema version is missing")
	}
}

func TestWriteSyft_Descriptor(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Descriptor struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if doc.Descriptor.Name != "sbomlyze" {
		t.Errorf("Descriptor name = %q, want %q", doc.Descriptor.Name, "sbomlyze")
	}
	if doc.Descriptor.Version != "convert" {
		t.Errorf("Descriptor version = %q, want %q", doc.Descriptor.Version, "convert")
	}
}

func TestWriteSyft_Schema(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo())
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Schema struct {
			Version string `json:"version"`
			URL     string `json:"url"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if doc.Schema.Version == "" {
		t.Error("Schema version is empty")
	}
	if doc.Schema.URL == "" {
		t.Error("Schema URL is empty")
	}
}

func TestWriteSyft_ArtifactIDGeneration(t *testing.T) {
	tests := []struct {
		name   string
		comp   sbom.Component
		wantID string
	}{
		{
			name:   "uses BOMRef when set",
			comp:   sbom.Component{Name: "pkg", BOMRef: "custom-ref"},
			wantID: "custom-ref",
		},
		{
			name:   "falls back to PURL",
			comp:   sbom.Component{Name: "pkg", PURL: "pkg:npm/pkg@1.0"},
			wantID: "pkg:npm/pkg@1.0",
		},
		{
			name:   "falls back to name-version",
			comp:   sbom.Component{Name: "pkg", Version: "1.0"},
			wantID: "pkg-1.0",
		},
		{
			name:   "falls back to name only",
			comp:   sbom.Component{Name: "pkg"},
			wantID: "pkg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteSyft(&buf, []sbom.Component{tt.comp}, sbom.SBOMInfo{})
			if err != nil {
				t.Fatalf("WriteSyft failed: %v", err)
			}

			var doc struct {
				Artifacts []struct {
					ID string `json:"id"`
				} `json:"artifacts"`
			}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			if doc.Artifacts[0].ID != tt.wantID {
				t.Errorf("Artifact ID = %q, want %q", doc.Artifacts[0].ID, tt.wantID)
			}
		})
	}
}

func TestWriteSyft_SchemaVersionFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo()); err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Schema struct {
			Version string `json:"version"`
			URL     string `json:"url"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	parts := strings.Split(doc.Schema.Version, ".")
	if len(parts) != 3 {
		t.Errorf("Schema version = %q, want MODEL.REVISION.ADDITION format (3 parts)", doc.Schema.Version)
	}
	if !strings.Contains(doc.Schema.URL, "anchore/syft") {
		t.Errorf("Schema URL = %q, should reference anchore/syft", doc.Schema.URL)
	}
	if !strings.HasSuffix(doc.Schema.URL, ".json") {
		t.Errorf("Schema URL = %q, should end with .json", doc.Schema.URL)
	}
}

func TestWriteSyft_MultipleLicenses(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:     "test",
			Version:  "1.0",
			Licenses: []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
	}
	if err := WriteSyft(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			Licenses []struct {
				Value          string `json:"value"`
				SPDXExpression string `json:"spdxExpression"`
			} `json:"licenses"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	a := doc.Artifacts[0]
	if len(a.Licenses) != 3 {
		t.Fatalf("license count = %d, want 3", len(a.Licenses))
	}
	want := []string{"MIT", "Apache-2.0", "BSD-3-Clause"}
	for i, lic := range a.Licenses {
		if lic.Value != want[i] {
			t.Errorf("license[%d].value = %q, want %q", i, lic.Value, want[i])
		}
		if lic.SPDXExpression != want[i] {
			t.Errorf("license[%d].spdxExpression = %q, want %q", i, lic.SPDXExpression, want[i])
		}
	}
}

func TestWriteSyft_MultipleCPEs(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:    "test",
			Version: "1.0",
			CPEs: []string{
				"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:other:product:1.0:*:*:*:*:*:*:*",
			},
		},
	}
	if err := WriteSyft(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			CPEs []struct {
				CPE string `json:"cpe"`
			} `json:"cpes"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	a := doc.Artifacts[0]
	if len(a.CPEs) != 2 {
		t.Fatalf("CPE count = %d, want 2", len(a.CPEs))
	}
	if a.CPEs[0].CPE != "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" {
		t.Errorf("cpes[0] = %q", a.CPEs[0].CPE)
	}
	if a.CPEs[1].CPE != "cpe:2.3:a:other:product:1.0:*:*:*:*:*:*:*" {
		t.Errorf("cpes[1] = %q", a.CPEs[1].CPE)
	}
}

func TestWriteSyft_MultipleLocations(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{
			Name:      "test",
			Version:   "1.0",
			Locations: []string{"/usr/lib/test.so", "/opt/test/lib.so", "/var/cache/test"},
		},
	}
	if err := WriteSyft(&buf, comps, sbom.SBOMInfo{}); err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	locs := doc.Artifacts[0].Locations
	if len(locs) != 3 {
		t.Fatalf("location count = %d, want 3", len(locs))
	}
	wantPaths := []string{"/usr/lib/test.so", "/opt/test/lib.so", "/var/cache/test"}
	for i, loc := range locs {
		if loc.Path != wantPaths[i] {
			t.Errorf("locations[%d].path = %q, want %q", i, loc.Path, wantPaths[i])
		}
	}
}

func TestWriteSyft_FilesArrayPresent(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSyft(&buf, sampleSyftComponents(), sampleSyftInfo()); err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	files, ok := raw["files"].([]interface{})
	if !ok {
		t.Fatal("files is not an array or is missing")
	}
	if len(files) != 0 {
		t.Errorf("files should be empty, got %d entries", len(files))
	}
}

func TestWriteSyft_EmptyLocationsAndLicenses(t *testing.T) {
	var buf bytes.Buffer
	comps := []sbom.Component{
		{Name: "test", Version: "1.0"},
	}
	err := WriteSyft(&buf, comps, sbom.SBOMInfo{})
	if err != nil {
		t.Fatalf("WriteSyft failed: %v", err)
	}

	var doc struct {
		Artifacts []struct {
			Locations []interface{} `json:"locations"`
			Licenses  []interface{} `json:"licenses"`
			CPEs      []interface{} `json:"cpes"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	a := doc.Artifacts[0]
	if a.Locations == nil {
		t.Error("Locations should be empty array, not null")
	}
	if a.Licenses == nil {
		t.Error("Licenses should be empty array, not null")
	}
	if a.CPEs == nil {
		t.Error("CPEs should be empty array, not null")
	}
}
