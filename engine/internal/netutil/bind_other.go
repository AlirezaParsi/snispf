//go:build !linux

package netutil

import "syscall"

// BindToDeviceControl is a no-op off Linux (SO_BINDTODEVICE is Linux/Android).
func BindToDeviceControl(_ string) func(network, address string, c syscall.RawConn) error {
	return nil
}
