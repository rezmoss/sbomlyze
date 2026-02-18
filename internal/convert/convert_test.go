package convert

import (
	"bytes"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Format
		wantErr bool
	}{
		{name: "cyclonedx", input: "cyclonedx", want: FormatCycloneDX},
		{name: "cdx alias", input: "cdx", want: FormatCycloneDX},
		{name: "spdx", input: "spdx", want: FormatSPDX},
		{name: "syft", input: "syft", want: FormatSyft},
		{name: "case insensitive cyclonedx", input: "CycloneDX", want: FormatCycloneDX},
		{name: "case insensitive CDX", input: "CDX", want: FormatCycloneDX},
		{name: "case insensitive SPDX", input: "SPDX", want: FormatSPDX},
		{name: "case insensitive Syft", input: "SYFT", want: FormatSyft},
		{name: "with whitespace", input: "  spdx  ", want: FormatSPDX},
		{name: "unknown format", input: "csv", wantErr: true},
		{name: "empty string", input: "", wantErr: true},
		{name: "random string", input: "foobar", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFormat(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFormat(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseFormat(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("ParseFormat(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestConvert_Dispatch(t *testing.T) {
	comps := []sbom.Component{
		{
			Name:    "test-pkg",
			Version: "1.0.0",
			PURL:    "pkg:npm/test-pkg@1.0.0",
			BOMRef:  "test-pkg@1.0.0",
		},
	}
	info := sbom.SBOMInfo{
		SourceName: "test-source",
		SourceType: "directory",
	}

	tests := []struct {
		name   string
		format Format
	}{
		{name: "CycloneDX", format: FormatCycloneDX},
		{name: "SPDX", format: FormatSPDX},
		{name: "Syft", format: FormatSyft},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := Convert(&buf, comps, info, tt.format)
			if err != nil {
				t.Fatalf("Convert to %s failed: %v", tt.name, err)
			}
			if buf.Len() == 0 {
				t.Errorf("Convert to %s produced empty output", tt.name)
			}
		})
	}
}

func TestConvert_InvalidFormat(t *testing.T) {
	comps := []sbom.Component{
		{Name: "test", Version: "1.0"},
	}
	info := sbom.SBOMInfo{}

	var buf bytes.Buffer
	err := Convert(&buf, comps, info, Format(99))
	if err == nil {
		t.Error("Convert with invalid format should return error, got nil")
	}
}

func TestFormatString(t *testing.T) {
	tests := []struct {
		format Format
		want   string
	}{
		{FormatCycloneDX, "cyclonedx"},
		{FormatSPDX, "spdx"},
		{FormatSyft, "syft"},
		{Format(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.format.String()
			if got != tt.want {
				t.Errorf("Format(%d).String() = %q, want %q", tt.format, got, tt.want)
			}
		})
	}
}

func TestConvert_EmptyComponents(t *testing.T) {
	var comps []sbom.Component
	info := sbom.SBOMInfo{}

	formats := []struct {
		name   string
		format Format
	}{
		{"CycloneDX", FormatCycloneDX},
		{"SPDX", FormatSPDX},
		{"Syft", FormatSyft},
	}

	for _, tt := range formats {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := Convert(&buf, comps, info, tt.format)
			if err != nil {
				t.Fatalf("Convert with empty components to %s failed: %v", tt.name, err)
			}
			if buf.Len() == 0 {
				t.Errorf("Convert with empty components to %s produced empty output", tt.name)
			}
		})
	}
}
