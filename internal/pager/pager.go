package pager

import (
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mattn/go-isatty"
)

// Pager pipes stdout through an external pager (e.g. less).
type Pager struct {
	cmd       *exec.Cmd
	pipe      *os.File
	oldStdout *os.File
	stopped   bool
}

// resolve: $SBOMLYZE_PAGER > $PAGER > "less"
func resolve() string {
	if p := os.Getenv("SBOMLYZE_PAGER"); p != "" {
		return p
	}
	if p := os.Getenv("PAGER"); p != "" {
		return p
	}
	return "less"
}

// Start spawns a pager and redirects os.Stdout to it.
// Returns nil if disabled, stdout is not a TTY, or pager is ""/cat.
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

	// Set LESS=FRX if not already set:
	//   F = quit if output fits one screen
	//   R = display raw ANSI color codes
	//   X = don't clear screen on exit
	cmd.Env = os.Environ()
	if _, ok := os.LookupEnv("LESS"); !ok {
		cmd.Env = append(cmd.Env, "LESS=FRX")
	}
	if _, ok := os.LookupEnv("LV"); !ok {
		cmd.Env = append(cmd.Env, "LV=-c")
	}

	// Ignore SIGPIPE so writes to a closed pager pipe don't kill us
	signal.Ignore(syscall.SIGPIPE)

	if err := cmd.Start(); err != nil {
		_ = w.Close()
		_ = r.Close()
		return nil
	}

	// Close read end in parent — the pager process owns it now
	_ = r.Close()

	oldStdout := os.Stdout
	os.Stdout = w

	return &Pager{
		cmd:       cmd,
		pipe:      w,
		oldStdout: oldStdout,
	}
}

// Stop restores os.Stdout and waits for the pager to exit.
// Safe to call on nil or multiple times.
func (p *Pager) Stop() {
	if p == nil || p.stopped {
		return
	}
	p.stopped = true

	os.Stdout = p.oldStdout
	_ = p.pipe.Close()
	_ = p.cmd.Wait()
}
