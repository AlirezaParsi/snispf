//go:build !linux

package platform

func hasAFPacketSupport() bool {
	return false
}
