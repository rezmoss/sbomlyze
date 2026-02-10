package sbom

import (
	"encoding/json"
	"fmt"
	"testing"
)

// generateSyntheticCycloneDX creates a valid CycloneDX JSON document with n components.
func generateSyntheticCycloneDX(n int) []byte {
	components := make([]map[string]interface{}, n)
	for i := 0; i < n; i++ {
		components[i] = map[string]interface{}{
			"type":    "library",
			"name":    fmt.Sprintf("pkg-%d", i),
			"version": fmt.Sprintf("%d.0.0", i%100),
			"purl":    fmt.Sprintf("pkg:npm/pkg-%d@%d.0.0", i, i%100),
			"bom-ref": fmt.Sprintf("ref-%d", i),
			"licenses": []map[string]interface{}{
				{"license": map[string]string{"id": "MIT"}},
			},
			"hashes": []map[string]string{
				{"alg": "SHA-256", "content": fmt.Sprintf("abc%ddef", i)},
			},
		}
	}
	doc := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.4",
		"components":  components,
	}
	data, _ := json.Marshal(doc)
	return data
}

// generateSyntheticSyft creates a valid Syft JSON document with n artifacts.
func generateSyntheticSyft(n int) []byte {
	artifacts := make([]map[string]interface{}, n)
	for i := 0; i < n; i++ {
		artifacts[i] = map[string]interface{}{
			"id":      fmt.Sprintf("id-%d", i),
			"name":    fmt.Sprintf("pkg-%d", i),
			"version": fmt.Sprintf("%d.0.0", i%100),
			"type":    "apk",
			"purl":    fmt.Sprintf("pkg:apk/alpine/pkg-%d@%d.0.0", i, i%100),
			"foundBy": "test-cataloger",
			"licenses": []map[string]string{
				{"value": "MIT", "spdxExpression": "MIT"},
			},
			"cpes": []map[string]string{
				{"cpe": fmt.Sprintf("cpe:2.3:a:vendor:pkg-%d:%d.0.0:*:*:*:*:*:*:*", i, i%100)},
			},
		}
	}
	doc := map[string]interface{}{
		"artifacts": artifacts,
		"source": map[string]interface{}{
			"type":   "image",
			"target": map[string]string{"userInput": "test:latest"},
		},
	}
	data, _ := json.Marshal(doc)
	return data
}

// Benchmarks

func BenchmarkParseCycloneDX(b *testing.B) {
	sizes := []int{100, 1000, 5000, 10000}
	for _, n := range sizes {
		data := generateSyntheticCycloneDX(n)
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				_, err := ParseCycloneDX(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkParseSyft(b *testing.B) {
	sizes := []int{100, 1000, 5000, 10000}
	for _, n := range sizes {
		data := generateSyntheticSyft(n)
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				_, err := ParseSyft(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFormatDetection_LargeFile(b *testing.B) {
	data := generateSyntheticCycloneDX(10000)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		IsCycloneDX(data)
		IsSPDX(data)
		IsSyft(data)
	}
}

func BenchmarkNormalize(b *testing.B) {
	data := generateSyntheticCycloneDX(10000)
	comps, err := ParseCycloneDX(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NormalizeComponents(comps)
	}
}

func BenchmarkDiffComponents(b *testing.B) {
	dataBefore := generateSyntheticCycloneDX(5000)
	dataAfter := generateSyntheticCycloneDX(5000)
	compsBefore, _ := ParseCycloneDX(dataBefore)
	compsAfter, _ := ParseCycloneDX(dataAfter)
	compsBefore = NormalizeComponents(compsBefore)
	compsAfter = NormalizeComponents(compsAfter)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(compsBefore) && j < len(compsAfter); j++ {
			CompareComponents(compsBefore[j], compsAfter[j])
		}
	}
}

// Correctness tests for large SBOMs

func TestLargeSBOM_CycloneDX_10000(t *testing.T) {
	data := generateSyntheticCycloneDX(10000)
	comps, err := ParseCycloneDX(data)
	if err != nil {
		t.Fatalf("failed to parse 10k CycloneDX: %v", err)
	}
	if len(comps) != 10000 {
		t.Fatalf("expected 10000 components, got %d", len(comps))
	}

	// Normalize all
	normalized := NormalizeComponents(comps)
	if len(normalized) != 10000 {
		t.Fatalf("normalization changed count: %d", len(normalized))
	}

	// Verify all have names, PURLs, and IDs
	for i, c := range normalized {
		if c.Name == "" {
			t.Errorf("component %d has empty name", i)
		}
		if c.PURL == "" {
			t.Errorf("component %d has empty PURL", i)
		}
		if c.ID == "" {
			t.Errorf("component %d has empty ID", i)
		}
	}
}

func TestLargeSBOM_Syft_10000(t *testing.T) {
	data := generateSyntheticSyft(10000)
	comps, err := ParseSyft(data)
	if err != nil {
		t.Fatalf("failed to parse 10k Syft: %v", err)
	}
	if len(comps) != 10000 {
		t.Fatalf("expected 10000 components, got %d", len(comps))
	}

	// Normalize all
	normalized := NormalizeComponents(comps)
	if len(normalized) != 10000 {
		t.Fatalf("normalization changed count: %d", len(normalized))
	}

	// Verify all have names, PURLs, and IDs
	for i, c := range normalized {
		if c.Name == "" {
			t.Errorf("component %d has empty name", i)
		}
		if c.PURL == "" {
			t.Errorf("component %d has empty PURL", i)
		}
		if c.ID == "" {
			t.Errorf("component %d has empty ID", i)
		}
	}
}

func TestLargeSBOM_FormatDetection(t *testing.T) {
	cdxData := generateSyntheticCycloneDX(10000)
	syftData := generateSyntheticSyft(10000)

	if !IsCycloneDX(cdxData) {
		t.Error("failed to detect large CycloneDX")
	}
	if IsSPDX(cdxData) {
		t.Error("large CycloneDX falsely detected as SPDX")
	}
	if IsSyft(cdxData) {
		t.Error("large CycloneDX falsely detected as Syft")
	}

	if !IsSyft(syftData) {
		t.Error("failed to detect large Syft")
	}
	if IsCycloneDX(syftData) {
		t.Error("large Syft falsely detected as CycloneDX")
	}
	if IsSPDX(syftData) {
		t.Error("large Syft falsely detected as SPDX")
	}
}
