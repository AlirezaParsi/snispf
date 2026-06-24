//go:build windows

package rawinjector

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"snispf/internal/logx"
)

const (
	winDivertLayerNetwork = 0

	winDivertFlagSniff    = 1
	winDivertFlagRecvOnly = 4
	winDivertFlagSendOnly = 8

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

type winDivertAddress [64]byte

type winPortState struct {
	synSeq      uint32
	synSeen     bool
	fakeHello   []byte
	fakeSent    bool
	confirmedC  chan struct{}
	failedC     chan struct{}
	confirmOnce sync.Once
	failOnce    sync.Once
	lastAddr    winDivertAddress
	mu          sync.Mutex
}

type winInjector struct {
	localIPVal atomic.Uint32 // packed big-endian IPv4; 0 = unset
	remoteIP   [4]byte
	remotePort int

	sniffHandle atomic.Uintptr
	sendHandle  atomic.Uintptr

	ports   map[int]*winPortState
	portsMu sync.RWMutex

	running atomic.Bool
	wg      sync.WaitGroup
}

var (
	winDivertDLL        = syscall.NewLazyDLL("WinDivert.dll")
	procWinDivertOpen   = winDivertDLL.NewProc("WinDivertOpen")
	procWinDivertRecv   = winDivertDLL.NewProc("WinDivertRecv")
	procWinDivertSend   = winDivertDLL.NewProc("WinDivertSend")
	procWinDivertClose  = winDivertDLL.NewProc("WinDivertClose")
	procHelperChecksums = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
)

func New(localIP, remoteIP string, remotePort int, _ func(string) []byte) Interface {
	out := &winInjector{
		remotePort: remotePort,
		ports:      make(map[int]*winPortState),
	}
	if lip := net.ParseIP(localIP).To4(); lip != nil {
		out.localIPVal.Store(ipToUint32(lip))
	}
	if rip := net.ParseIP(remoteIP).To4(); rip != nil {
		copy(out.remoteIP[:], rip)
	}
	return out
}

func ipToUint32(ip net.IP) uint32 {
	if len(ip) < 4 {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func (i *winInjector) localIPBytes() [4]byte {
	v := i.localIPVal.Load()
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// refreshLocalIP re-resolves the source IP used to reach the remote endpoint.
// Returns true if the resolved address differs from what we had cached. Used
// to keep the userspace localIP guard accurate across VPN toggle, DHCP renew,
// or multi-WAN switches — the kernel filter is now broad enough not to need
// reopening, so we just update the in-memory comparison value.
func (i *winInjector) refreshLocalIP() bool {
	if i.remoteIP == [4]byte{} {
		return false
	}
	remote := net.IP(i.remoteIP[:]).String()
	c, err := net.Dial("udp4", net.JoinHostPort(remote, "53"))
	if err != nil {
		return false
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP == nil {
		return false
	}
	lip := ua.IP.To4()
	if lip == nil {
		return false
	}
	newVal := ipToUint32(lip)
	old := i.localIPVal.Swap(newVal)
	return old != newVal
}

func IsRawAvailable() bool {
	if err := winDivertDLL.Load(); err != nil {
		setRawDiagnostic(fmt.Sprintf("WinDivert load failed: %v", err))
		return false
	}
	h, err := winDivertOpenWithFallback(
		[]string{"false"},
		[]uint64{winDivertFlagSendOnly},
	)
	if err != nil {
		setRawDiagnostic(fmt.Sprintf("WinDivert open failed (admin/driver/version mismatch?): %v", err))
		return false
	}
	_ = winDivertClose(h)
	setRawDiagnostic("")
	return true
}

func (i *winInjector) Start() bool {
	if i.sniffHandle.Load() != 0 && i.sendHandle.Load() != 0 {
		setRawDiagnostic("")
		return true
	}
	if i.remoteIP == [4]byte{} {
		setRawDiagnostic("invalid remote IPv4 for WinDivert injector")
		return false
	}
	if i.localIPVal.Load() == 0 {
		// Best-effort resolve via route; if it still fails we proceed (the
		// userspace guard will simply allow more packets through to handlePacket
		// until the next refresh succeeds).
		i.refreshLocalIP()
	}
	if err := winDivertDLL.Load(); err != nil {
		setRawDiagnostic(fmt.Sprintf("WinDivert load failed: %v", err))
		return false
	}

	remote := net.IP(i.remoteIP[:]).String()
	// Broad filter: anything to/from the remote endpoint on the configured
	// remote port. localIP is NOT in the kernel filter so the handle keeps
	// capturing after a VPN/DHCP/multi-WAN local-IP change. handlePacket
	// applies the userspace localIP guard (M8/M4) to discard cross-flow noise.
	sniffFilter := fmt.Sprintf(
		"tcp and ((ip.SrcAddr == %s and tcp.SrcPort == %d) or (ip.DstAddr == %s and tcp.DstPort == %d))",
		remote, i.remotePort, remote, i.remotePort,
	)

	sniff, err := winDivertOpenWithFallback(
		[]string{sniffFilter, "ip and tcp"},
		[]uint64{winDivertFlagSniff | winDivertFlagRecvOnly, winDivertFlagSniff},
	)
	if err != nil {
		setRawDiagnostic(fmt.Sprintf("WinDivert sniff open failed (admin/driver/version mismatch?): %v", err))
		return false
	}
	send, err := winDivertOpenWithFallback(
		[]string{"false"},
		[]uint64{winDivertFlagSendOnly},
	)
	if err != nil {
		_ = winDivertClose(sniff)
		setRawDiagnostic(fmt.Sprintf("WinDivert send open failed (admin/driver/version mismatch?): %v", err))
		return false
	}
	i.sniffHandle.Store(uintptr(sniff))
	i.sendHandle.Store(uintptr(send))
	i.running.Store(true)
	setRawDiagnostic("")
	i.wg.Add(1)
	go i.sniffLoop()
	i.wg.Add(1)
	go i.localIPRefreshLoop()
	return true
}

// localIPRefreshLoop periodically re-resolves the local source IP toward the
// remote so the userspace filter stays accurate across network changes.
// 5s cadence is a compromise: fast enough to catch a VPN toggle in practice,
// slow enough that the per-tick UDP-dial cost is negligible.
func (i *winInjector) localIPRefreshLoop() {
	defer i.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if !i.running.Load() {
			return
		}
		<-ticker.C
		if !i.running.Load() {
			return
		}
		if i.refreshLocalIP() {
			lip := i.localIPBytes()
			logx.Infof("raw injector (windows): local IP refreshed to %d.%d.%d.%d", lip[0], lip[1], lip[2], lip[3])
		}
	}
}

func (i *winInjector) Stop() {
	if !i.running.Swap(false) {
		return
	}
	sniff := i.sniffHandle.Swap(0)
	if sniff != 0 {
		_ = winDivertClose(syscall.Handle(sniff))
	}
	send := i.sendHandle.Swap(0)
	if send != 0 {
		_ = winDivertClose(syscall.Handle(send))
	}
	i.wg.Wait()
}

func (i *winInjector) RegisterPort(localPort int, fakeHello []byte) bool {
	i.portsMu.Lock()
	defer i.portsMu.Unlock()
	if _, exists := i.ports[localPort]; exists {
		return false
	}
	i.ports[localPort] = &winPortState{
		fakeHello:  append([]byte(nil), fakeHello...),
		confirmedC: make(chan struct{}),
		failedC:    make(chan struct{}),
	}
	return true
}

func (i *winInjector) WaitForConfirmation(localPort int, timeout time.Duration) bool {
	return i.WaitForConfirmationDetailed(localPort, timeout) == ConfirmationStatusConfirmed
}

func (i *winInjector) WaitForConfirmationDetailed(localPort int, timeout time.Duration) ConfirmationStatus {
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

func (i *winInjector) CleanupPort(localPort int) {
	i.portsMu.Lock()
	defer i.portsMu.Unlock()
	delete(i.ports, localPort)
}

// SetInterfaceName is a no-op on Windows. WinDivert captures at the network
// layer and does not require interface-level pinning.
func (i *winInjector) SetInterfaceName(_ string) {}

func (i *winInjector) markFailed(ps *winPortState) {
	ps.failOnce.Do(func() {
		close(ps.failedC)
	})
}

func (i *winInjector) sniffLoop() {
	defer i.wg.Done()
	buf := make([]byte, 65535)
	for i.running.Load() {
		h := i.sniffHandle.Load()
		if h == 0 {
			return
		}
		var readLen uint32
		var addr winDivertAddress
		r1, _, _ := procWinDivertRecv.Call(
			h,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&readLen)),
			uintptr(unsafe.Pointer(&addr)),
		)
		if r1 == 0 || readLen == 0 {
			if !i.running.Load() {
				return
			}
			continue
		}
		if int(readLen) > len(buf) {
			continue
		}
		// No upfront copy: handlePacket retains bytes only when scheduling a
		// fake-send, and that path already copies the template separately.
		i.handlePacket(buf[:readLen], addr)
	}
}

func (i *winInjector) handlePacket(pkt []byte, addr winDivertAddress) {
	if len(pkt) < 40 || (pkt[0]>>4) != 4 {
		return
	}
	if pkt[9] != ipProtoTCP {
		return
	}
	ihl := ipHeaderLen(pkt)
	if len(pkt) < ihl+20 {
		return
	}
	tcp := pkt[ihl:]
	tcpHdrLen := int((tcp[12] >> 4) * 4)
	if len(tcp) < tcpHdrLen || tcpHdrLen < 20 {
		return
	}

	flags := tcp[13]
	payloadLen := len(tcp) - tcpHdrLen
	srcIP := pkt[12:16]
	dstIP := pkt[16:20]
	srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
	dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))

	localIP := i.localIPBytes()
	outbound := equal4(dstIP, i.remoteIP[:]) && dstPort == i.remotePort
	inbound := equal4(srcIP, i.remoteIP[:]) && srcPort == i.remotePort

	// Userspace localIP guard (M4 + M8 equivalent on Windows). If we have a
	// resolved local IP, packets that don't carry it on the right side are
	// either cross-flow noise or pre-IP-change leftovers; drop them. If
	// localIP is still unset, fall through to preserve behavior.
	if localIP != [4]byte{} {
		if outbound && !equal4(srcIP, localIP[:]) {
			return
		}
		if inbound && !equal4(dstIP, localIP[:]) {
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
			if ps.fakeSent {
				ps.mu.Unlock()
				return
			}
			if !ps.synSeen || seq != ps.synSeq+1 {
				ps.mu.Unlock()
				return
			}
			ps.fakeSent = true
			ps.lastAddr = addr
			isn := ps.synSeq
			fake := append([]byte(nil), ps.fakeHello...)
			sendAddr := ps.lastAddr
			ps.mu.Unlock()

			tpl := append([]byte(nil), pkt...)
			go func() {
				time.Sleep(1 * time.Millisecond)
				frame, err := buildFakePacket(tpl, isn, fake)
				if err != nil {
					i.markFailed(ps)
					return
				}
				if err := winDivertCalcChecksums(frame); err != nil {
					i.markFailed(ps)
					return
				}
				if err := i.injectPacket(frame, sendAddr); err != nil {
					i.markFailed(ps)
				}
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
			confirmed := ps.fakeSent && ackNum == ps.synSeq+1
			ps.mu.Unlock()
			if confirmed {
				ps.confirmOnce.Do(func() { close(ps.confirmedC) })
			}
			return
		}
		if (flags & tcpRST) != 0 {
			i.portsMu.RLock()
			ps := i.ports[dstPort]
			i.portsMu.RUnlock()
			if ps != nil {
				i.markFailed(ps)
			}
		}
	}
}

func (i *winInjector) injectPacket(packet []byte, addr winDivertAddress) error {
	h := i.sendHandle.Load()
	if h == 0 {
		return syscall.EBADF
	}
	var writeLen uint32
	r1, _, e := procWinDivertSend.Call(
		h,
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&writeLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r1 == 0 {
		if e != nil {
			return e
		}
		return syscall.EINVAL
	}
	if int(writeLen) != len(packet) {
		return syscall.EIO
	}
	return nil
}

func winDivertCalcChecksums(packet []byte) error {
	r1, _, e := procHelperChecksums.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		0,
		0,
	)
	if r1 == 0 {
		if e != nil {
			return e
		}
		return syscall.EINVAL
	}
	return nil
}

func winDivertOpen(filter string, layer uint32, priority int16, flags uint64) (syscall.Handle, error) {
	p, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	r1, _, e := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	h := syscall.Handle(r1)
	if h == 0 || h == syscall.InvalidHandle {
		if e != nil {
			return 0, e
		}
		return 0, syscall.EINVAL
	}
	return h, nil
}

func winDivertOpenWithFallback(filters []string, flagsList []uint64) (syscall.Handle, error) {
	attempts := make([]string, 0, len(filters)*len(flagsList))
	for _, f := range filters {
		for _, fl := range flagsList {
			h, err := winDivertOpen(f, winDivertLayerNetwork, 0, fl)
			if err == nil {
				return h, nil
			}
			attempts = append(attempts, fmt.Sprintf("filter=%q flags=%d err=%v", f, fl, err))
		}
	}
	if len(attempts) == 0 {
		return 0, syscall.EINVAL
	}
	return 0, fmt.Errorf("all WinDivertOpen attempts failed: %s", strings.Join(attempts, "; "))
}

func winDivertClose(h syscall.Handle) error {
	r1, _, e := procWinDivertClose.Call(uintptr(h))
	if r1 == 0 {
		if e != nil {
			return e
		}
		return syscall.EINVAL
	}
	return nil
}

func buildFakePacket(template []byte, isn uint32, fakePayload []byte) ([]byte, error) {
	if len(template) < 40 {
		return nil, syscall.EINVAL
	}
	ipOff := 0
	ihl := ipHeaderLen(template)
	tcpOff := ipOff + ihl
	if len(template) < tcpOff+20 {
		return nil, syscall.EINVAL
	}
	tcpHdrLen := int((template[tcpOff+12] >> 4) * 4)
	if len(template) < tcpOff+tcpHdrLen {
		return nil, syscall.EINVAL
	}

	headers := append([]byte(nil), template[:tcpOff+tcpHdrLen]...)
	out := append(headers, fakePayload...)

	binary.BigEndian.PutUint16(out[ipOff+2:ipOff+4], uint16(len(out)-ipOff))
	oldID := binary.BigEndian.Uint16(out[ipOff+4 : ipOff+6])
	binary.BigEndian.PutUint16(out[ipOff+4:ipOff+6], oldID+1)

	out[ipOff+10] = 0
	out[ipOff+11] = 0
	binary.BigEndian.PutUint16(out[ipOff+10:ipOff+12], ipChecksum(out[ipOff:ipOff+ihl]))

	out[tcpOff+13] |= tcpPSH
	seq := isn + 1 - uint32(len(fakePayload))
	binary.BigEndian.PutUint32(out[tcpOff+4:tcpOff+8], seq)

	out[tcpOff+16] = 0
	out[tcpOff+17] = 0
	binary.BigEndian.PutUint16(out[tcpOff+16:tcpOff+18], tcpChecksum(out[ipOff:ipOff+ihl], out[tcpOff:]))

	return out, nil
}
