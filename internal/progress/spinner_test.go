package progress

import (
	"sync"
	"testing"
	"time"
)

func TestDisabledSpinnerIsNoop(t *testing.T) {
	s := &Spinner{disabled: true}
	// None of these should panic or produce output
	s.Start("test")
	s.Stop()
	s.Start("test2")
	s.Done("done")
}

func TestStartStop(t *testing.T) {
	// Force-enable spinner (bypass TTY check)
	s := &Spinner{}
	s.Start("loading...")
	time.Sleep(200 * time.Millisecond)
	s.Stop()
}

func TestStartDone(t *testing.T) {
	s := &Spinner{}
	s.Start("loading...")
	time.Sleep(200 * time.Millisecond)
	s.Done("finished")
}

func TestDoubleStop(t *testing.T) {
	s := &Spinner{}
	s.Start("loading...")
	time.Sleep(100 * time.Millisecond)
	s.Stop()
	s.Stop() // should not panic
}

func TestStopWithoutStart(t *testing.T) {
	s := &Spinner{}
	s.Stop() // should not panic
	s.Done("nothing") // should not panic
}

func TestConcurrentAccess(t *testing.T) {
	s := &Spinner{}
	s.Start("concurrent")

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond)
			s.Stop()
		}()
	}
	wg.Wait()
}

func TestSequentialStartStop(t *testing.T) {
	s := &Spinner{}
	s.Start("phase 1")
	time.Sleep(100 * time.Millisecond)
	s.Done("phase 1 done")

	s.Start("phase 2")
	time.Sleep(100 * time.Millisecond)
	s.Done("phase 2 done")
}
