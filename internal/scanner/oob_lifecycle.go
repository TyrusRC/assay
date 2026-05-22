package scanner

import (
	"fmt"
	"os"
	"time"

	"github.com/TyrusRC/assay/internal/detection/oob"
)

// startOOBClientAsync starts OOB client initialization in the background.
// It signals completion via the oobReady channel.
func (s *InternalScanner) startOOBClientAsync() {
	if !s.config.EnableOOB {
		return
	}

	s.mu.Lock()
	if s.oobReady != nil {
		s.mu.Unlock()
		return // Already started
	}
	s.oobReady = make(chan struct{})
	s.mu.Unlock()

	go func() {
		defer close(s.oobReady)

		oobClient, err := oob.NewClient()
		s.mu.Lock()
		defer s.mu.Unlock()

		if err != nil {
			s.oobInitErr = err
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[!] OOB testing unavailable: %v\n", err)
			}
		} else {
			s.oobClient = oobClient
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[+] OOB testing enabled with URL: %s\n", oobClient.GetURL())
			}
		}
	}()
}

// waitForOOBClient waits for OOB client to be ready with a timeout.
// Returns true if OOB client is available, false otherwise.
func (s *InternalScanner) waitForOOBClient(timeout time.Duration) bool {
	s.mu.Lock()
	oobReady := s.oobReady
	s.mu.Unlock()
	if oobReady == nil {
		return false
	}

	select {
	case <-oobReady:
		s.mu.Lock()
		available := s.oobClient != nil
		s.mu.Unlock()
		return available
	case <-time.After(timeout):
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] OOB initialization timeout after %v\n", timeout)
		}
		return false
	}
}
