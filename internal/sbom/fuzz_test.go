package sbom

import (
	"os"
	"testing"
)

// FuzzParseDataWithInfo exercises format detection and every parser
// (CycloneDX JSON/XML, SPDX, Syft) with arbitrary input. Parsers must
// return an error on bad input, never panic or hang.
func FuzzParseDataWithInfo(f *testing.F) {
	seeds := []string{
		"cyclonedx-before.json",
		"cyclonedx-before.xml",
		"cyclonedx-with-metadata.json",
		"spdx-sample.json",
		"spdx-complex.json",
		"syft-sample.json",
		"syft-malformed-artifact.json",
		"empty.json",
		"invalid.json",
		"malformed.json",
		"not-json.txt",
	}
	for _, name := range seeds {
		data, err := os.ReadFile(testdataPath(name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"bomFormat":"CycloneDX"}`))
	f.Add([]byte(`{"spdxVersion":"SPDX-2.3"}`))
	f.Add([]byte(`{"artifacts":[],"source":{}}`))
	f.Add([]byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.5"></bom>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		components, _, err := ParseDataWithInfo(data)
		if err != nil && components != nil {
			t.Fatalf("returned components alongside error: %v", err)
		}
	})
}
