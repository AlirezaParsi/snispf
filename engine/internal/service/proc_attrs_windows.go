//go:build windows

package service

import (
	"os/exec"
	"syscall"
)

func setHiddenProcessAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
}
