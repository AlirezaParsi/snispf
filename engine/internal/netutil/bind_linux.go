//go:build linux

package netutil

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// BindToDeviceControl returns a net.Dialer.Control hook that pins the socket to
// the named WAN interface via SO_BINDTODEVICE, forcing egress out the physical
// NIC regardless of a VPN tun owning the default route. Needs root/CAP_NET_RAW.
// Empty name returns nil (no binding).
func BindToDeviceControl(ifname string) func(network, address string, c syscall.RawConn) error {
	ifname = strings.TrimSpace(ifname)
	if ifname == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.BindToDevice(int(fd), ifname)
		}); err != nil {
			return err
		}
		return serr
	}
}
