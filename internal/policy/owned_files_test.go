package policy

import (
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/analysis"
)

func TestDenyOwnedFileDrift(t *testing.T) {
	drift := func(config string) analysis.DiffResult {
		return analysis.DiffResult{OwnedFileDrift: []analysis.OwnedFileDrift{{
			Name: "coreutils", Version: "9.1-1",
			Files: []analysis.OwnedFileChange{{Path: "/usr/bin/ls", Change: analysis.FileModified, Config: config}},
		}}}
	}
	if v := Evaluate(Policy{}, drift(analysis.ConfigNo)); len(v) != 0 {
		t.Errorf("rule is opt-in, got %+v", v)
	}
	v := Evaluate(Policy{DenyOwnedFileDrift: true}, drift(analysis.ConfigNo))
	if len(v) != 1 || v[0].Rule != "deny_owned_file_drift" || v[0].Severity != SeverityError || !strings.Contains(v[0].Message, "/usr/bin/ls") {
		t.Fatalf("violations = %+v", v)
	}
	if v := Evaluate(Policy{DenyOwnedFileDrift: true}, drift(analysis.ConfigUnknown)); len(v) != 1 {
		t.Errorf("unknown config status must still gate, got %+v", v)
	}
	if v := Evaluate(Policy{DenyOwnedFileDrift: true}, drift(analysis.ConfigYes)); len(v) != 0 {
		t.Errorf("config files are skipped by default, got %+v", v)
	}
	if v := Evaluate(Policy{DenyOwnedFileDrift: true, OwnedFileDriftIncludeConfig: true}, drift(analysis.ConfigYes)); len(v) != 1 {
		t.Errorf("include_config must gate config files, got %+v", v)
	}
	if p, err := Load([]byte(`{"deny_owned_file_drift": true, "owned_file_drift_include_config": true}`)); err != nil || !p.DenyOwnedFileDrift || !p.OwnedFileDriftIncludeConfig {
		t.Errorf("load = %+v, %v", p, err)
	}
}
