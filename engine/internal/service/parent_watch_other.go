//go:build !windows

package service

func parentProcessAlive(pid int, expectedStartUnixMS int64) bool {
	_ = pid
	_ = expectedStartUnixMS
	return true
}
