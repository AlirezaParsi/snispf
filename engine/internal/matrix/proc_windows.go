//go:build windows

package matrix

import (
	"os/exec"
	"time"
)

// setProcGroup is a no-op on Windows (no POSIX process groups).
func setProcGroup(_ *exec.Cmd) {}

// terminate kills the child; Windows releases the WinDivert handle on exit.
func terminate(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}
