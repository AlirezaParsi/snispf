//go:build !windows

package service

import "os/exec"

func setHiddenProcessAttrs(cmd *exec.Cmd) {
	_ = cmd
}
