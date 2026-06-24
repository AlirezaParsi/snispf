//go:build !windows

package matrix

import (
	"os/exec"
	"syscall"
	"time"
)

// setProcGroup puts the child in its own process group so we can signal the
// whole group (the core may have helper goroutines/children).
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminate SIGTERMs the child's process group so the core can tear down its
// iptables/nfqueue, then SIGKILLs if it lingers.
func terminate(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
	}
}
