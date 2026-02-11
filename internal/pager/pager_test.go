package pager

import (
	"os"
	"testing"
)

func TestResolve_SbomlyzeEnvVar(t *testing.T) {
	t.Setenv("SBOMLYZE_PAGER", "more")
	t.Setenv("PAGER", "cat")
	if got := resolve(); got != "more" {
		t.Errorf("resolve() = %q, want %q", got, "more")
	}
}

func TestResolve_PagerEnvVar(t *testing.T) {
	// Clear tool-specific var
	t.Setenv("SBOMLYZE_PAGER", "")
	t.Setenv("PAGER", "more -s")
	if got := resolve(); got != "more -s" {
		t.Errorf("resolve() = %q, want %q", got, "more -s")
	}
}

func TestResolve_Default(t *testing.T) {
	t.Setenv("SBOMLYZE_PAGER", "")
	t.Setenv("PAGER", "")
	if got := resolve(); got != "less" {
		t.Errorf("resolve() = %q, want %q", got, "less")
	}
}

func TestStart_DisabledReturnsNil(t *testing.T) {
	p := Start(true)
	if p != nil {
		t.Error("Start(true) should return nil")
		p.Stop()
	}
}

func TestStart_NonTTYReturnsNil(t *testing.T) {
	// In test environments, stdout is typically not a TTY
	if f, err := os.CreateTemp("", "test"); err == nil {
		oldStdout := os.Stdout
		os.Stdout = f
		defer func() {
			os.Stdout = oldStdout
			_ = f.Close()
			_ = os.Remove(f.Name())
		}()

		p := Start(false)
		if p != nil {
			t.Error("Start with non-TTY stdout should return nil")
			p.Stop()
		}
	}
}

func TestStart_CatPagerReturnsNil(t *testing.T) {
	t.Setenv("SBOMLYZE_PAGER", "cat")
	// Even if stdout were a TTY, "cat" means no paging
	p := Start(false)
	if p != nil {
		t.Error("Start with pager=cat should return nil")
		p.Stop()
	}
}

func TestStop_NilReceiver(t *testing.T) {
	var p *Pager
	p.Stop() // must not panic
}

func TestStop_Idempotent(t *testing.T) {
	var p *Pager
	p.Stop()
	p.Stop() // double call must not panic
}
