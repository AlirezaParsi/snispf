package rawinjector

import "time"

type ConfirmationStatus string

const (
	ConfirmationStatusConfirmed     ConfirmationStatus = "confirmed"
	ConfirmationStatusFailed        ConfirmationStatus = "failed"
	ConfirmationStatusTimeout       ConfirmationStatus = "timeout"
	ConfirmationStatusNotRegistered ConfirmationStatus = "not_registered"
)

type DetailedWaiter interface {
	WaitForConfirmationDetailed(localPort int, timeout time.Duration) ConfirmationStatus
}

type PortStateDebugger interface {
	DebugPortState(localPort int) string
}

// InterfaceNameSetter is optionally implemented by platform injectors that
// support pinning the capture/send path to a specific network interface by
// name (e.g. "usb0", "eth0"). Call before Start().
type InterfaceNameSetter interface {
	SetInterfaceName(name string)
}

type Interface interface {
	Start() bool
	Stop()
	// RegisterPort installs per-port state for confirmation tracking. Returns
	// false if the port is already registered (collision), in which case the
	// caller should release the port and retry with a fresh reservation —
	// silently overwriting would clobber another flow's confirmation channels.
	RegisterPort(localPort int, fakeHello []byte) bool
	WaitForConfirmation(localPort int, timeout time.Duration) bool
	WaitForConfirmationDetailed(localPort int, timeout time.Duration) ConfirmationStatus
	CleanupPort(localPort int)
}
