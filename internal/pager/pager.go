package pager

import (
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mattn/go-isatty"
)

// Pager pipes stdout through a pager.
type Pager struct {
	cmd       *exec.Cmd
	pipe      *os.File
	oldStdout *os.File
	stopped   bool
}

func resolve() string {
	if p := os.Getenv("SBOMLYZE_PAGER"); p != "" {
		return p
	}
	if p := os.Getenv("PAGER"); p != "" {
		return p
	}
	return "less"
}

// Start spawns a pager and redirects os.Stdout.
func Start(disabled bool) *Pager {
	if disabled || !isatty.IsTerminal(os.Stdout.Fd()) {
		return nil
	}

	pagerCmd := resolve()
	if pagerCmd == "" || pagerCmd == "cat" {
		return nil
	}

	args := strings.Fields(pagerCmd)

	r, w, err := os.Pipe()
	if err != nil {
		return nil
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = r
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// LESS=FRX: quit-if-fits, raw-ANSI, no-clear
	cmd.Env = os.Environ()
	if _, ok := os.LookupEnv("LESS"); !ok {
		cmd.Env = append(cmd.Env, "LESS=FRX")
	}
	if _, ok := os.LookupEnv("LV"); !ok {
		cmd.Env = append(cmd.Env, "LV=-c")
	}

	signal.Ignore(syscall.SIGPIPE)

	if err := cmd.Start(); err != nil {
		_ = w.Close()
		_ = r.Close()
		return nil
	}

	_ = r.Close()

	oldStdout := os.Stdout
	os.Stdout = w

	return &Pager{
		cmd:       cmd,
		pipe:      w,
		oldStdout: oldStdout,
	}
}

// Stop restores os.Stdout. Safe to call on nil.
func (p *Pager) Stop() {
	if p == nil || p.stopped {
		return
	}
	p.stopped = true

	os.Stdout = p.oldStdout
	_ = p.pipe.Close()
	_ = p.cmd.Wait()
}
