package netutil

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// GetDefaultInterfaceIPv4 returns the source IPv4 address used to reach dest.
func GetDefaultInterfaceIPv4(dest string) string {
	c, err := net.Dial("udp4", net.JoinHostPort(dest, "53"))
	if err != nil {
		return ""
	}
	defer c.Close()
	if addr, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// ResolveHost resolves a hostname to its IPv4 address, preferring v4.
func ResolveHost(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return host
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ips[0].String()
}

// IsValidPort checks whether a port number is in the valid TCP range.
func IsValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// ParseHostPort parses a HOST:PORT string with fallback defaults.
func ParseHostPort(addr, defaultHost string, defaultPort int) (string, int, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return defaultHost, defaultPort, nil
	}
	if strings.HasPrefix(addr, ":") {
		p, err := strconv.Atoi(addr[1:])
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %q", addr)
		}
		return defaultHost, p, nil
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, defaultPort, nil
	}
	host := addr[:i]
	if host == "" {
		host = defaultHost
	}
	p, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return "", 0, fmt.Errorf("invalid address: %q", addr)
	}
	return host, p, nil
}
