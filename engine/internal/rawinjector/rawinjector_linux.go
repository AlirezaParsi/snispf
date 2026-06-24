//go:build linux

package rawinjector

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"snispf/internal/logx"
)

const (
	ethPIP  = 0x0800
	ethPAll = 0x0003

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10

	// AF_PACKET socket options not exposed in Go's syscall package.
	solPacket           = 0x107
	packetAddMembership = 1
	packetMrPromisc     = 1
	packetStatistics    = 6
	soRcvbufForce       = 33

	// Target receive buffer for AF_PACKET capture. With promiscuous mode on,
	// brief WAN bursts can outpace the default kernel buffer and silently drop
	// packets; bumping to 8MB gives ample headroom for typical traffic.
	rcvbufTarget = 8 * 1024 * 1024
)

// tpacketStats mirrors struct tpacket_stats from <linux/if_packet.h>.
type tpacketStats struct {
	Packets uint32
	Drops   uint32
}

// packetMreq mirrors C struct packet_mreq (see linux/if_packet.h).
type packetMreq struct {
	Ifindex int32
	Type    uint16
	Alen    uint16
	Address [8]byte
}

type portState struct {
	synSeq       uint32
	synSeen      bool
	fakeHello    []byte
	fakeSent     bool
	mismatchSeen bool
	lastOutSeq   uint32
	lastAckNum   uint32
	lastFlags    uint8
	lastPayload  int
	lastEvent    string
	confirmedC   chan struct{}
	failedC      chan struct{}
	confirmOnce  sync.Once
	failOnce     sync.Once
	mu           sync.Mutex
}

type injector struct {
	localIP    [4]byte
	remoteIP   [4]byte
	remotePort int

	fd            atomic.Int64 // AF_PACKET socket for capture (sniffLoop)
	sendFd        atomic.Int64 // AF_INET SOCK_RAW for injection; -1 = use AF_PACKET fallback
	ifIndex       int
	interfaceName string // optional: pin to named interface (e.g. "usb0")
	routeMu       sync.Mutex

	// Cached route resolution result for chooseSendIfindex. Only consulted
	// when interfaceName is empty (auto-detect mode). Refreshed when expired
	// or invalidated by a send error.
	routeCacheValid    bool
	routeCacheLocalIP  [4]byte
	routeCacheIfindex  int
	routeCacheExpireAt time.Time

	// Track which ifindexes have had promiscuous mode enabled
	// to avoid redundant setsockopt calls.
	promiscSet map[int]bool

	ports   map[int]*portState
	portsMu sync.RWMutex

	running atomic.Bool
	wg      sync.WaitGroup
}

func New(localIP, remoteIP string, remotePort int, _ func(string) []byte) Interface {
	out := &injector{
		remotePort: remotePort,
		ports:      make(map[int]*portState),
		promiscSet: make(map[int]bool),
	}
	out.fd.Store(-1)
	out.sendFd.Store(-1)
	if lip := net.ParseIP(localIP).To4(); lip != nil {
		copy(out.localIP[:], lip)
	}
	if rip := net.ParseIP(remoteIP).To4(); rip != nil {
		copy(out.remoteIP[:], rip)
	}
	return out
}

// SetInterfaceName pins the capture/send path to the named network interface.
// Must be called before Start(). On multi-WAN routers this overrides the
// automatic route-based interface detection.
func (i *injector) SetInterfaceName(name string) {
	i.interfaceName = name
}

// enablePromiscuous adds PACKET_MR_PROMISC membership for the given ifindex
// on the AF_PACKET file descriptor. Safe to call multiple times per ifindex;
// redundant calls are deduplicated.
func (i *injector) enablePromiscuous(fd, ifindex int) {
	if ifindex <= 0 || i.promiscSet[ifindex] {
		return
	}
	mreq := packetMreq{
		Ifindex: int32(ifindex),
		Type:    packetMrPromisc,
	}
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(solPacket),
		uintptr(packetAddMembership),
		uintptr(unsafe.Pointer(&mreq)),
		unsafe.Sizeof(mreq),
		0,
	)
	if errno != 0 {
		logx.Warnf("raw injector: failed to set promiscuous mode on ifindex=%d: %v (capture may miss forwarded packets)", ifindex, errno)
		return
	}
	i.promiscSet[ifindex] = true
}

func IsRawAvailable() bool {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(ethPAll)))
	if err != nil {
		return false
	}
	_ = syscall.Close(fd)
	return true
}

func (i *injector) Start() bool {
	if i.fd.Load() >= 0 {
		return true
	}
	if i.remoteIP == [4]byte{} {
		setRawDiagnostic("linux raw injector: remote IPv4 is empty/invalid")
		return false
	}

	// Use SOCK_DGRAM so the kernel provides network-layer packets without
	// requiring fixed L2 frame assumptions. This is more robust on PPP-like WANs.
	// Use ETH_P_ALL so capture still sees IPv4 traffic on PPPoE/mixed link-layer
	// paths where ETH_P_IP filtering can miss packets.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(ethPAll)))
	if err != nil {
		setRawDiagnostic(fmt.Sprintf("linux raw injector socket(AF_PACKET,SOCK_DGRAM) failed: %v", err))
		return false
	}

	// Bump receive buffer to absorb promiscuous-capture bursts. SO_RCVBUFFORCE
	// bypasses the rmem_max ceiling when running as root (typical on OpenWrt
	// or systemd services). Fall back to plain SO_RCVBUF if we lack the
	// capability — losing the bypass is acceptable; failing the syscall isn't.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soRcvbufForce, rcvbufTarget); err != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvbufTarget)
	}

	// Determine which interface to bind to:
	// 1. If an explicit interfaceName was set (e.g. "usb0"), resolve it directly.
	// 2. Otherwise, auto-detect via routing table.
	idx := 0
	if i.interfaceName != "" {
		if itf, err := net.InterfaceByName(i.interfaceName); err != nil {
			logx.Warnf("raw injector: interface %q not found: %v; falling back to route detection", i.interfaceName, err)
			idx = i.findRouteInterfaceIndex()
		} else {
			idx = itf.Index
			logx.Infof("raw injector: using explicit interface %s (ifindex=%d)", i.interfaceName, idx)
			// Also resolve the interface's IPv4 address as localIP if not already set.
			if i.localIP == [4]byte{} {
				if addrs, err := itf.Addrs(); err == nil {
					for _, a := range addrs {
						if ipNet, ok := a.(*net.IPNet); ok {
							if ip4 := ipNet.IP.To4(); ip4 != nil {
								copy(i.localIP[:], ip4)
								break
							}
						}
					}
				}
			}
		}
	} else {
		idx = i.findRouteInterfaceIndex()
	}

	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  idx,
	}); err != nil {
		// Fallback to all interfaces capture to survive route/interface churn.
		if err2 := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: 0}); err2 != nil {
			setRawDiagnostic(fmt.Sprintf("linux raw injector bind failed for ifindex=%d (%v) and any-if (%v)", idx, err, err2))
			_ = syscall.Close(fd)
			return false
		}
		idx = 0
	}

	// Enable promiscuous mode on the capture interface(s).
	// On router/forwarding setups (e.g. OpenWrt), the return ACK from the
	// upstream server arrives on the WAN interface (usb0, pppoe-wan, etc.)
	// with an ethernet destination MAC addressed to the upstream gateway/modem,
	// NOT the router's own MAC. Without promiscuous mode the NIC's MAC filter
	// silently drops these frames before AF_PACKET sees them, causing
	// wrong_seq confirmation timeouts.
	if idx > 0 {
		i.enablePromiscuous(fd, idx)
	} else {
		// Wildcard capture: enable promisc on every non-loopback interface
		// so forwarded packets aren't dropped by any NIC's MAC filter.
		if interfaces, err := net.Interfaces(); err == nil {
			for _, itf := range interfaces {
				if itf.Flags&net.FlagLoopback != 0 {
					continue
				}
				i.enablePromiscuous(fd, itf.Index)
			}
		}
	}

	if i.localIP == [4]byte{} {
		if lip, _, ok := i.routeLocalIPAndIndex(); ok {
			copy(i.localIP[:], lip[:])
		}
	}

	i.fd.Store(int64(fd))
	i.ifIndex = idx

	// Create a dedicated AF_INET SOCK_RAW socket for fake packet injection.
	// AF_PACKET sendto (the previous approach) builds an Ethernet frame with
	// the destination MAC taken from SockaddrLinklayer.Haddr. Because Haddr
	// was never populated, the frame went out with dst MAC = 00:00:00:00:00:00.
	// On direct Ethernet this sometimes works (the switch/NIC may accept it),
	// but on USB-tethered phones (RNDIS), PPPoE tunnels, USB modems, and
	// other virtual WAN interfaces common on OpenWrt, the gateway device
	// drops the frame at L2 — the fake packet never reaches the server and
	// wrong_seq confirmation times out.
	//
	// The raw IP socket operates at L3: the kernel handles routing, ARP/ND
	// neighbor resolution, and link-layer framing automatically for any
	// interface type. IP_HDRINCL tells the kernel we supply the full IP
	// header (including our own checksums) so the TCP payload and sequence
	// numbers are preserved exactly as buildFakeFrame produces them.
	sendMethod := "af_packet_fallback"
	rawFd, rawErr := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if rawErr == nil {
		if err := syscall.SetsockoptInt(rawFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			_ = syscall.Close(rawFd)
			rawFd = -1
			logx.Warnf("raw injector: IP_HDRINCL failed (%v); using AF_PACKET for send", err)
		} else {
			// Pin the raw send socket to the WAN device too. Without this the
			// fake packet follows the routing table — which, under a FULL-TUNNEL
			// VPN, points at the tun, so the decoy gets tunneled and the DPI on
			// the physical wire never sees it (bypass silently fails). The
			// capture path is already on this interface's ifindex.
			if i.interfaceName != "" {
				if err := syscall.SetsockoptString(rawFd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, i.interfaceName); err != nil {
					logx.Warnf("raw injector: SO_BINDTODEVICE %s on send socket failed: %v; fake packets may take the default route (VPN tun)", i.interfaceName, err)
				} else {
					logx.Infof("raw injector: send socket bound to %s (escapes VPN tun)", i.interfaceName)
				}
			}
			i.sendFd.Store(int64(rawFd))
			sendMethod = "ip_raw"
		}
	} else {
		logx.Warnf("raw injector: AF_INET SOCK_RAW unavailable (%v); using AF_PACKET for send", rawErr)
	}

	i.running.Store(true)
	i.wg.Add(1)
	go i.sniffLoop()
	i.wg.Add(1)
	go i.statsLoop()
	if i.interfaceName != "" {
		logx.Infof("raw injector active on interface=%s ifindex=%d send_method=%s", i.interfaceName, idx, sendMethod)
	} else if idx == 0 {
		logx.Infof("raw injector active with wildcard capture send_method=%s", sendMethod)
	} else {
		logx.Infof("raw injector active on ifindex=%d send_method=%s", idx, sendMethod)
	}
	setRawDiagnostic("")
	return true
}

func (i *injector) routeLocalIPAndIndex() ([4]byte, int, bool) {
	var out [4]byte
	if i.remoteIP == [4]byte{} {
		return out, 0, false
	}
	remote := net.IP(i.remoteIP[:]).String()
	c, err := net.Dial("udp4", net.JoinHostPort(remote, "53"))
	if err != nil {
		return out, 0, false
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP == nil {
		return out, 0, false
	}
	lip := ua.IP.To4()
	if lip == nil {
		return out, 0, false
	}
	idx := findInterfaceIndexByIP(lip)
	if idx == 0 {
		return out, 0, false
	}
	copy(out[:], lip)
	return out, idx, true
}

func findInterfaceIndexByIP(target net.IP) int {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, itf := range interfaces {
		addrs, err := itf.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipNet.IP.To4(); ip4 != nil && ip4.Equal(target) {
				return itf.Index
			}
		}
	}
	return 0
}

func (i *injector) findRouteInterfaceIndex() int {
	if _, idx, ok := i.routeLocalIPAndIndex(); ok {
		return idx
	}
	return i.findInterfaceIndex()
}

func (i *injector) findInterfaceIndex() int {
	if i.localIP == [4]byte{} {
		return 0
	}
	target := net.IP(i.localIP[:])
	return findInterfaceIndexByIP(target)
}

func (i *injector) chooseSendIfindex() int {
	i.routeMu.Lock()
	defer i.routeMu.Unlock()
	fd := int(i.fd.Load())
	// When an explicit interface name is set, resolve it each time to handle
	// interface re-creation (e.g. USB modem reconnect) but don't fall back
	// to route-based detection.
	if i.interfaceName != "" {
		if itf, err := net.InterfaceByName(i.interfaceName); err == nil {
			if itf.Index != i.ifIndex {
				logx.Warnf("raw injector: interface %s ifindex changed old=%d new=%d", i.interfaceName, i.ifIndex, itf.Index)
				i.ifIndex = itf.Index
				// Re-apply promiscuous mode on the new ifindex.
				if fd >= 0 {
					i.enablePromiscuous(fd, itf.Index)
				}
			}
		}
		return i.ifIndex
	}
	// Auto-detect path: serve from cache if still valid.
	if i.routeCacheValid && time.Now().Before(i.routeCacheExpireAt) {
		i.ifIndex = i.routeCacheIfindex
		i.localIP = i.routeCacheLocalIP
		return i.ifIndex
	}
	if lip, idx, ok := i.routeLocalIPAndIndex(); ok {
		if idx != i.ifIndex {
			logx.Warnf("raw injector send route changed old_ifindex=%d new_ifindex=%d", i.ifIndex, idx)
			// Re-apply promiscuous mode on the new route interface so
			// forwarded return packets are still captured.
			if fd >= 0 {
				i.enablePromiscuous(fd, idx)
			}
		}
		i.ifIndex = idx
		copy(i.localIP[:], lip[:])
		i.routeCacheLocalIP = lip
		i.routeCacheIfindex = idx
		i.routeCacheExpireAt = time.Now().Add(time.Second)
		i.routeCacheValid = true
	}
	return i.ifIndex
}

func (i *injector) invalidateRouteCache() {
	i.routeMu.Lock()
	i.routeCacheValid = false
	i.routeMu.Unlock()
}

func (i *injector) Stop() {
	if !i.running.Swap(false) {
		return
	}
	fd := i.fd.Swap(-1)
	if fd >= 0 {
		_ = syscall.Close(int(fd))
	}
	sFd := i.sendFd.Swap(-1)
	if sFd >= 0 {
		_ = syscall.Close(int(sFd))
	}
	// Reset promisc membership tracking so a subsequent Start() on a fresh
	// fd re-applies PACKET_MR_PROMISC. Without this, internal recovery
	// silently loses promiscuous mode and capture misses forwarded packets.
	i.promiscSet = make(map[int]bool)
	i.wg.Wait()
}

func (i *injector) RegisterPort(localPort int, fakeHello []byte) bool {
	i.portsMu.Lock()
	defer i.portsMu.Unlock()
	if _, exists := i.ports[localPort]; exists {
		return false
	}
	i.ports[localPort] = &portState{
		fakeHello:  append([]byte(nil), fakeHello...),
		confirmedC: make(chan struct{}),
		failedC:    make(chan struct{}),
	}
	return true
}

func (i *injector) WaitForConfirmation(localPort int, timeout time.Duration) bool {
	return i.WaitForConfirmationDetailed(localPort, timeout) == ConfirmationStatusConfirmed
}

func (i *injector) WaitForConfirmationDetailed(localPort int, timeout time.Duration) ConfirmationStatus {
	i.portsMu.RLock()
	ps := i.ports[localPort]
	i.portsMu.RUnlock()
	if ps == nil {
		return ConfirmationStatusNotRegistered
	}
	if timeout <= 0 {
		select {
		case <-ps.confirmedC:
			return ConfirmationStatusConfirmed
		case <-ps.failedC:
			return ConfirmationStatusFailed
		default:
			return ConfirmationStatusTimeout
		}
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ps.confirmedC:
		return ConfirmationStatusConfirmed
	case <-ps.failedC:
		return ConfirmationStatusFailed
	case <-t.C:
		return ConfirmationStatusTimeout
	}
}

func (i *injector) markFailed(ps *portState) {
	ps.mu.Lock()
	ps.lastEvent = "mark_failed"
	ps.mu.Unlock()
	ps.failOnce.Do(func() {
		close(ps.failedC)
	})
}

func (i *injector) DebugPortState(localPort int) string {
	i.portsMu.RLock()
	ps := i.ports[localPort]
	i.portsMu.RUnlock()
	if ps == nil {
		return "port_state=missing"
	}
	ps.mu.Lock()
	synSeen := ps.synSeen
	fakeSent := ps.fakeSent
	synSeq := ps.synSeq
	lastOutSeq := ps.lastOutSeq
	lastAckNum := ps.lastAckNum
	lastFlags := ps.lastFlags
	lastPayload := ps.lastPayload
	lastEvent := ps.lastEvent
	ps.mu.Unlock()

	confirmed := channelClosed(ps.confirmedC)
	failed := channelClosed(ps.failedC)

	return fmt.Sprintf(
		"raw_state={syn_seen=%t fake_sent=%t syn_seq=%d last_out_seq=%d last_ack=%d last_flags=0x%02x last_payload=%d confirmed=%t failed=%t last_event=%q}",
		synSeen, fakeSent, synSeq, lastOutSeq, lastAckNum, lastFlags, lastPayload, confirmed, failed, lastEvent,
	)
}

func (i *injector) CleanupPort(localPort int) {
	i.portsMu.Lock()
	defer i.portsMu.Unlock()
	delete(i.ports, localPort)
}

func (i *injector) sniffLoop() {
	defer i.wg.Done()
	buf := make([]byte, 65536)
	for i.running.Load() {
		fd := int(i.fd.Load())
		if fd < 0 {
			return
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if i.running.Load() {
				continue
			}
			return
		}
		// No upfront copy: handlePacket only retains bytes when it builds a
		// fake-send template, and that path already does its own copy at
		// buildFakeFrame time. Avoids ~65KB worth of allocs per captured packet
		// under promiscuous capture on a busy WAN link.
		i.handlePacket(buf[:n])
	}
}

// statsLoop periodically reads PACKET_STATISTICS to surface kernel-side
// capture drops. tp_drops > 0 means the socket's receive buffer overflowed and
// packets were lost before sniffLoop could read them; under promiscuous
// capture on a busy WAN link this is the canary for missed confirmations.
func (i *injector) statsLoop() {
	defer i.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var totalDrops uint64
	for {
		select {
		case <-ticker.C:
			if !i.running.Load() {
				return
			}
			fd := int(i.fd.Load())
			if fd < 0 {
				return
			}
			var st tpacketStats
			sz := uint32(unsafe.Sizeof(st))
			_, _, errno := syscall.RawSyscall6(
				syscall.SYS_GETSOCKOPT,
				uintptr(fd),
				uintptr(solPacket),
				uintptr(packetStatistics),
				uintptr(unsafe.Pointer(&st)),
				uintptr(unsafe.Pointer(&sz)),
				0,
			)
			if errno != 0 {
				continue
			}
			if st.Drops > 0 {
				totalDrops += uint64(st.Drops)
				logx.Warnf("raw injector capture drops interval=%d total=%d packets=%d", st.Drops, totalDrops, st.Packets)
			}
		}
		if !i.running.Load() {
			return
		}
	}
}

func (i *injector) handlePacket(pkt []byte) {
	ipOff := ipv4Offset(pkt)
	if ipOff < 0 {
		return
	}
	ip := pkt[ipOff:]
	if len(ip) < 20 || (ip[0]>>4) != 4 || ip[9] != ipProtoTCP {
		return
	}
	ihl := ipHeaderLen(ip)
	if len(ip) < ihl+20 {
		return
	}
	tcp := ip[ihl:]
	tcpHdrLen := int((tcp[12] >> 4) * 4)
	if len(tcp) < tcpHdrLen || tcpHdrLen < 20 {
		return
	}

	flags := tcp[13]
	payloadLen := len(tcp) - tcpHdrLen
	srcIP := ip[12:16]
	dstIP := ip[16:20]
	srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
	dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))

	if !equal4(srcIP, i.remoteIP[:]) && !equal4(dstIP, i.remoteIP[:]) {
		return
	}

	i.portsMu.RLock()
	_, hasSrc := i.ports[srcPort]
	_, hasDst := i.ports[dstPort]
	i.portsMu.RUnlock()

	outbound := equal4(dstIP, i.remoteIP[:]) && dstPort == i.remotePort && hasSrc
	inbound := equal4(srcIP, i.remoteIP[:]) && srcPort == i.remotePort && hasDst

	// On forwarding routers (OpenWrt) the wildcard/promisc capture also sees
	// LAN-side flows that happen to share remote IP/port with ours. Guard
	// with localIP so we only act on packets that belong to this injector's
	// own connections. localIP is the address we bound the outbound socket
	// to (or the resolved route source). If localIP is unset (zero), fall
	// through and accept — preserves behaviour on hosts where we couldn't
	// determine the source IP.
	if i.localIP != [4]byte{} {
		if outbound && !equal4(srcIP, i.localIP[:]) {
			return
		}
		if inbound && !equal4(dstIP, i.localIP[:]) {
			return
		}
	}

	if outbound {
		seq := binary.BigEndian.Uint32(tcp[4:8])

		if (flags&tcpSYN) != 0 && (flags&tcpACK) == 0 {
			i.portsMu.RLock()
			ps := i.ports[srcPort]
			i.portsMu.RUnlock()
			if ps != nil {
				ps.mu.Lock()
				ps.synSeq = seq
				ps.synSeen = true
				ps.lastOutSeq = seq
				ps.lastFlags = flags
				ps.lastPayload = payloadLen
				ps.lastEvent = "outbound_syn_seen"
				ps.mu.Unlock()
			}
			return
		}

		if (flags&tcpACK) != 0 && (flags&(tcpSYN|tcpFIN|tcpRST)) == 0 && payloadLen == 0 {
			i.portsMu.RLock()
			ps := i.ports[srcPort]
			i.portsMu.RUnlock()
			if ps == nil {
				return
			}
			ps.mu.Lock()
			ps.lastOutSeq = seq
			ps.lastFlags = flags
			ps.lastPayload = payloadLen
			if ps.fakeSent {
				ps.lastEvent = "outbound_ack_seen_after_fake"
				ps.mu.Unlock()
				return
			}
			if !ps.synSeen {
				ps.lastEvent = "outbound_ack_before_syn"
				ps.mu.Unlock()
				return
			}
			if seq != ps.synSeq+1 {
				// First mismatch: tolerate (could be a retransmit) and wait
				// for a second matching ACK. On the second mismatch, mark
				// the flow failed so the forwarder can fail over without
				// waiting the full confirmation timeout.
				if !ps.mismatchSeen {
					ps.mismatchSeen = true
					ps.lastEvent = "outbound_ack_seq_mismatch"
					ps.mu.Unlock()
					return
				}
				ps.lastEvent = "outbound_ack_seq_mismatch_repeat"
				ps.mu.Unlock()
				i.markFailed(ps)
				return
			}
			ps.fakeSent = true
			isn := ps.synSeq
			fake := append([]byte(nil), ps.fakeHello...)
			ps.lastEvent = "fake_send_scheduled"
			ps.mu.Unlock()

			tpl := append([]byte(nil), ip...)
			go func() {
				time.Sleep(1 * time.Millisecond)
				frame, err := buildFakeFrame(tpl, isn, fake)
				if err != nil {
					ps.mu.Lock()
					ps.lastEvent = "fake_build_failed"
					ps.mu.Unlock()
					i.markFailed(ps)
					return
				}
				if err := i.injectFrame(frame); err != nil {
					// Retry once with a refreshed ifindex — transient EAGAIN
					// or a stale route resolution shouldn't kill the flow.
					time.Sleep(2 * time.Millisecond)
					if err2 := i.injectFrame(frame); err2 != nil {
						ps.mu.Lock()
						ps.lastEvent = "fake_inject_failed"
						ps.mu.Unlock()
						i.markFailed(ps)
						return
					}
				}
				ps.mu.Lock()
				ps.lastEvent = "fake_injected"
				ps.mu.Unlock()
			}()
			return
		}
	}

	if inbound {
		ackNum := binary.BigEndian.Uint32(tcp[8:12])

		// Confirm on inbound ACK packets that are not SYN/FIN/RST.
		// Some servers send ACK+data as the first post-handshake packet; requiring
		// payloadLen==0 causes false timeouts in strict mode.
		if (flags&tcpACK) != 0 && (flags&(tcpSYN|tcpFIN|tcpRST)) == 0 {
			i.portsMu.RLock()
			ps := i.ports[dstPort]
			i.portsMu.RUnlock()
			if ps == nil {
				return
			}
			ps.mu.Lock()
			ps.lastAckNum = ackNum
			ps.lastFlags = flags
			ps.lastPayload = payloadLen
			ps.lastEvent = "inbound_ack_seen"
			confirmed := ps.fakeSent && ackNum == ps.synSeq+1
			if confirmed {
				ps.lastEvent = "confirmed_ack_match"
			}
			ps.mu.Unlock()
			if confirmed {
				ps.confirmOnce.Do(func() {
					close(ps.confirmedC)
				})
			}
			return
		}

		if (flags & tcpRST) != 0 {
			i.portsMu.RLock()
			ps := i.ports[dstPort]
			i.portsMu.RUnlock()
			if ps != nil {
				ps.mu.Lock()
				ps.lastAckNum = ackNum
				ps.lastFlags = flags
				ps.lastPayload = payloadLen
				ps.lastEvent = "inbound_rst_seen"
				ps.mu.Unlock()
				i.markFailed(ps)
			}
		}
	}
}

func channelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (i *injector) injectFrame(frame []byte) error {
	if len(frame) < 20 || (frame[0]>>4) != 4 {
		return syscall.EINVAL
	}

	// Prefer the AF_INET SOCK_RAW socket for injection. This operates at the
	// IP layer so the kernel handles routing, ARP/neighbor resolution, and
	// link-layer framing — works on any WAN type (RNDIS phone tethering, USB
	// modems, PPPoE, VLANs, etc.) without requiring the caller to know the
	// gateway's hardware address.
	sFd := int(i.sendFd.Load())
	if sFd >= 0 {
		var dstAddr [4]byte
		copy(dstAddr[:], frame[16:20])
		if err := syscall.Sendto(sFd, frame, 0, &syscall.SockaddrInet4{
			Addr: dstAddr,
		}); err != nil {
			return err
		}
		return nil
	}

	// Fallback: AF_PACKET sendto (original path). This works on plain
	// Ethernet interfaces where the switch/NIC accepts zero-MAC frames,
	// but fails on RNDIS, PPPoE, and other virtual WAN interfaces.
	fd := int(i.fd.Load())
	if fd < 0 {
		return syscall.EBADF
	}
	ifidx := i.chooseSendIfindex()
	if ifidx <= 0 {
		err := fmt.Errorf("linux raw injector: no route interface available for send")
		setRawDiagnostic(err.Error())
		return err
	}
	if err := syscall.Sendto(fd, frame, 0, &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  ifidx,
	}); err != nil {
		// Stale cached route may be the cause; drop the cache so the next
		// call (e.g. the M10 retry) re-resolves.
		i.invalidateRouteCache()
		return err
	}
	return nil
}

func buildFakeFrame(template []byte, isn uint32, fakePayload []byte) ([]byte, error) {
	if len(template) < 20 || (template[0]>>4) != 4 {
		return nil, syscall.EINVAL
	}
	ihl := ipHeaderLen(template)
	tcpOff := ihl
	if len(template) < tcpOff+20 {
		return nil, syscall.EINVAL
	}
	tcpHdrLen := int((template[tcpOff+12] >> 4) * 4)
	if len(template) < tcpOff+tcpHdrLen {
		return nil, syscall.EINVAL
	}

	headers := append([]byte(nil), template[:tcpOff+tcpHdrLen]...)
	out := append(headers, fakePayload...)

	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	oldID := binary.BigEndian.Uint16(out[4:6])
	binary.BigEndian.PutUint16(out[4:6], oldID+1)

	out[10] = 0
	out[11] = 0
	ipCk := ipChecksum(out[:ihl])
	binary.BigEndian.PutUint16(out[10:12], ipCk)

	out[tcpOff+13] |= tcpPSH
	seq := isn + 1 - uint32(len(fakePayload))
	binary.BigEndian.PutUint32(out[tcpOff+4:tcpOff+8], seq)

	out[tcpOff+16] = 0
	out[tcpOff+17] = 0
	tcpCk := tcpChecksum(out[:ihl], out[tcpOff:])
	binary.BigEndian.PutUint16(out[tcpOff+16:tcpOff+18], tcpCk)

	return out, nil
}

func ipv4Offset(pkt []byte) int {
	if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
		return 0
	}
	if len(pkt) >= 34 && binary.BigEndian.Uint16(pkt[12:14]) == ethPIP && (pkt[14]>>4) == 4 {
		return 14
	}
	return -1
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
