package netutil

import (
	"net"
	"strings"
	"time"
)

// physical WAN interface name prefixes (Android mobile data, wifi, ethernet).
var wanPrefixes = []string{"rmnet", "wlan", "wifi", "eth", "en", "wwan", "ccmni", "ap", "usb"}

// PhysicalWANInterface picks the live physical WAN device, skipping VPN tuns.
// Mobile interface names rotate (rmnet_data1/2 shuffle) and the default route
// often points at the tun, so when upstreamIP is given we probe EVERY candidate
// with a device-bound dial and return the one that connects FASTEST. Probing all
// (not just the first that connects) avoids a zombie rmnet left over from a SIM
// hot-swap — it has a stale IP that either won't connect or routes via a dead
// path (slow), so the live PDP wins. Falls back to the first physical candidate.
// Returns "" if none found.
func PhysicalWANInterface(upstreamIP string) string {
	cands := physicalCandidates()
	if len(cands) == 0 {
		return ""
	}
	if strings.TrimSpace(upstreamIP) != "" {
		best := ""
		var bestRTT time.Duration
		for _, dev := range cands {
			if rtt, ok := dialBoundRTT(dev, upstreamIP, 1500*time.Millisecond); ok && (best == "" || rtt < bestRTT) {
				best, bestRTT = dev, rtt
			}
		}
		if best != "" {
			return best
		}
	}
	return cands[0]
}

// ResolveWAN turns a config INTERFACE value into a concrete device name:
// "auto" probes the physical WAN (using probeIP), any other non-empty value is
// used verbatim, "" stays "" (route-based default).
func ResolveWAN(ifaceCfg, probeIP string) string {
	ifaceCfg = strings.TrimSpace(ifaceCfg)
	if strings.EqualFold(ifaceCfg, "auto") {
		return PhysicalWANInterface(probeIP)
	}
	return ifaceCfg
}

// WANIface is one selectable physical WAN interface.
type WANIface struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// WANInterfaces lists the physical WAN candidates (for a UI picker).
func WANInterfaces() []WANIface {
	var out []WANIface
	for _, name := range physicalCandidates() {
		out = append(out, WANIface{Name: name, IP: InterfaceIPv4(name)})
	}
	return out
}

// InterfaceIPv4 returns the first global IPv4 of the named interface, or "".
func InterfaceIPv4(name string) string {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	return ipv4Of(*ifc)
}

func physicalCandidates() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		ln := strings.ToLower(ifc.Name)
		if !hasAnyPrefix(ln, wanPrefixes) {
			continue
		}
		ip := ipv4Of(ifc)
		// Carriers legitimately use CGNAT/private IPs on mobile data, so only
		// reject tun sinkholes / loopback / link-local — not RFC1918.
		if ip == "" || isSinkholeIP(ip) {
			continue
		}
		out = append(out, ifc.Name)
	}
	return out
}

// dialBoundRTT dials upstreamIP:443 bound to dev and returns the connect time.
// ok is false if the bound dial fails (dead/zombie interface, or no path).
func dialBoundRTT(dev, upstreamIP string, to time.Duration) (time.Duration, bool) {
	d := net.Dialer{Timeout: to}
	if ctrl := BindToDeviceControl(dev); ctrl != nil {
		d.Control = ctrl
	}
	start := time.Now()
	c, err := d.Dial("tcp4", net.JoinHostPort(upstreamIP, "443"))
	if err != nil {
		return 0, false
	}
	_ = c.Close()
	return time.Since(start), true
}

func ipv4Of(ifc net.Interface) string {
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if v4 := n.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

var sinkholeNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{"198.18.0.0/15", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func isSinkholeIP(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return true
	}
	for _, n := range sinkholeNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}
