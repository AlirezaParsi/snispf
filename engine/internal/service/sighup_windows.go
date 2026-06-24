//go:build windows

package service

// Windows has no SIGHUP; nothing to ignore.
func ignoreHangup() {}
