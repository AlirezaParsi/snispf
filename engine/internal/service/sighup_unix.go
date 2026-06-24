//go:build !windows

package service

import (
	"os/signal"
	"syscall"
)

// ignoreHangup makes the control daemon survive its launching shell exiting.
// When the Magisk/KSU boot-service script returns, the process group can get a
// SIGHUP; the Go runtime's default action for SIGHUP is to terminate. The
// boot script also detaches us with setsid, but ignoring SIGHUP here means the
// daemon stays up regardless of how it was launched.
func ignoreHangup() {
	signal.Ignore(syscall.SIGHUP)
}
