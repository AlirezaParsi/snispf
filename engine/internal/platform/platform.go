package platform

import (
	"runtime"
	"syscall"
)

// Capabilities describes what DPI-bypass features the current platform supports.
type Capabilities struct {
	Platform      string
	Fragment      bool
	TLSRecordFrag bool
	FakeSNI       bool
	TCPNoDelay    bool
	RawSocket     bool
	IPTTLTrick    bool
	AFPacket      bool
	RawInjection  bool
}

// CheckCapabilities probes the current OS for available bypass capabilities.
func CheckCapabilities(rawInjectionAvailable bool) Capabilities {
	c := Capabilities{
		Platform:      runtime.GOOS,
		Fragment:      true,
		TLSRecordFrag: true,
		FakeSNI:       true,
		TCPNoDelay:    true,
		RawSocket:     false,
		IPTTLTrick:    false,
		AFPacket:      false,
		RawInjection:  rawInjectionAvailable,
	}

	if runtime.GOOS != "windows" {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
		if err == nil {
			c.RawSocket = true
			c.IPTTLTrick = true
			_ = syscall.Close(fd)
		}
	}

	if runtime.GOOS == "linux" {
		c.AFPacket = hasAFPacketSupport()
	}

	return c
}
