package progress

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
)

var frames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// Spinner displays a progress spinner on stderr.
type Spinner struct {
	disabled bool
	mu       sync.Mutex
	stop     chan struct{}
	stopped  chan struct{} // closed when goroutine exits
	once     sync.Once
	running  bool
	msg      string
}

// New creates a spinner. It is a no-op if disabled is true or stderr is not a TTY.
func New(disabled bool) *Spinner {
	if disabled || !isatty.IsTerminal(os.Stderr.Fd()) {
		return &Spinner{disabled: true}
	}
	return &Spinner{}
}

// Start begins displaying the spinner with the given message on stderr.
func (s *Spinner) Start(msg string) {
	if s.disabled {
		return
	}
	s.Stop()
	s.mu.Lock()
	s.msg = msg
	s.stop = make(chan struct{})
	s.stopped = make(chan struct{})
	s.once = sync.Once{}
	s.running = true
	stopCh := s.stop
	stoppedCh := s.stopped
	s.mu.Unlock()

	go func() {
		defer close(stoppedCh)
		i := 0
		for {
			select {
			case <-stopCh:
				return
			default:
				s.mu.Lock()
				fmt.Fprintf(os.Stderr, "\r%c %s", frames[i%len(frames)], s.msg)
				s.mu.Unlock()
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// Stop halts the spinner and clears its line.
func (s *Spinner) Stop() {
	if s.disabled {
		return
	}
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	stoppedCh := s.stopped
	s.mu.Unlock()

	s.once.Do(func() {
		close(s.stop)
		<-stoppedCh
		s.mu.Lock()
		fmt.Fprintf(os.Stderr, "\r%-*s\r", len(s.msg)+4, "")
		s.running = false
		s.mu.Unlock()
	})
}

// Done stops the spinner and prints a success message.
func (s *Spinner) Done(msg string) {
	if s.disabled {
		return
	}
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	stoppedCh := s.stopped
	s.mu.Unlock()

	s.once.Do(func() {
		close(s.stop)
		<-stoppedCh
		s.mu.Lock()
		fmt.Fprintf(os.Stderr, "\r✓ %s\n", msg)
		s.running = false
		s.mu.Unlock()
	})
}
