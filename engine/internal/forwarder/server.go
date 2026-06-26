package forwarder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"snispf/internal/bypass"
	"snispf/internal/config"
	"snispf/internal/logx"
	"snispf/internal/netutil"
	"snispf/internal/rawinjector"
	"snispf/internal/tlsutil"
)

// Counters accumulates relayed byte totals across all connections (and across
// runtime rebuilds, since the same pointer is shared with each new Server). Up =
// client→upstream, Down = upstream→client. The core flushes these to stats.json
// for the WebUI to derive live throughput.
type Counters struct {
	Up   atomic.Uint64
	Down atomic.Uint64
}

type Server struct {
	ListenHost       string
	ListenPort       int
	ConnectIP        string
	ConnectPort      int
	FakeSNI          string
	Endpoints        []config.Endpoint
	LoadBalance      string
	AutoFailover     bool
	FailoverRetries  int
	FakeSNIPool      []string // rotate decoy SNI per connection (empty = endpoint SNI)
	UTLSPool         []string // rotate fake-hello fingerprint per connection (empty = UTLS)
	InterfaceIP      string
	InterfaceName    string // WAN device for SO_BINDTODEVICE (escapes a VPN tun)
	Strategy         bypass.Strategy
	Injector         rawinjector.Interface
	Counters         *Counters // shared byte totals for throughput stats (nil = no counting)
	OnCriticalError  func(reason string)
	CriticalFailures int
	lbCounter        atomic.Uint64
	failureStreak    atomic.Uint64
	restartSent      atomic.Bool
	decoys           *decoyPool // health-tracked decoy rotation (built from FakeSNIPool)
	decoysOnce       sync.Once
}

// countingReader tallies bytes as they stream through, so a long-lived tunnel
// connection reports live throughput instead of only a final total at close.
type countingReader struct {
	r io.Reader
	n *atomic.Uint64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(uint64(n))
	}
	return n, err
}

func (s *Server) Run(ctx context.Context) error {
	laddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", s.ListenHost, s.ListenPort))
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp4", laddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	logx.Infof("listening on %s:%d", s.ListenHost, s.ListenPort)
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

// Handle serves one already-accepted connection. The daemon binds the listener
// once and dispatches here, swapping the active Server on WAN/endpoint rebuilds
// WITHOUT closing the listener — so local clients stay connectable even while the
// upstream path is rebinding (flapping mobile WAN, full-tunnel VPN escape).
func (s *Server) Handle(ctx context.Context, incoming *net.TCPConn) {
	s.handleConn(ctx, incoming)
}

func (s *Server) handleConn(ctx context.Context, incoming *net.TCPConn) {
	defer incoming.Close()
	_ = incoming.SetReadDeadline(time.Now().Add(30 * time.Second))
	first := make([]byte, 65535)
	n, err := incoming.Read(first)
	if err != nil || n == 0 {
		return
	}
	first = first[:n]
	_ = incoming.SetReadDeadline(time.Time{})

	parsed := tlsutil.ParseClientHello(first)
	logx.Debugf("incoming sni=%v bypass=%s", parsed["sni"], s.Strategy.Name())
	requestSNI, _ := parsed["sni"].(string)

	endpoints := s.endpointsOrDefault()
	base := s.pickBaseIndex(len(endpoints))
	retries := 0
	if len(endpoints) > 1 && strings.TrimSpace(s.LoadBalance) != "" {
		// When load balancing is configured and multiple endpoints are available,
		// attempt each endpoint once before dropping this connection.
		retries = len(endpoints) - 1
	}
	if s.AutoFailover && s.FailoverRetries > retries {
		retries = s.FailoverRetries
	}
	maxRetries := len(endpoints) - 1
	if retries > maxRetries {
		retries = maxRetries
	}
	totalAttempts := retries + 1

	var outgoing *net.TCPConn
	var selected config.Endpoint
	var registeredPort int
	registered := false
	// Defer cleanup of any still-registered port at function scope so a panic
	// inside Strategy.Apply (or any other unexpected exit) doesn't leak the
	// portState entry inside the raw injector.
	defer func() {
		if registered && s.Injector != nil {
			s.Injector.CleanupPort(registeredPort)
			registered = false
		}
	}()
	var lastConnectErr error
	var lastStrategyErr error
	for attempt := 0; attempt < totalAttempts; attempt++ {
		selected = endpoints[(base+attempt)%len(endpoints)]
		var reservedDecoy string // rotated decoy SNI used this attempt, for health tracking

		raddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", selected.IP, selected.Port))
		if err != nil {
			lastConnectErr = err
			logx.Warnf("upstream resolve failed endpoint=%s:%d err=%v", selected.IP, selected.Port, err)
			continue
		}

		dynamicIP := netutil.GetDefaultInterfaceIPv4(selected.IP)
		bindIP := s.InterfaceIP
		if s.Injector == nil && strings.TrimSpace(dynamicIP) != "" {
			// In non-raw modes, pick source IP per selected upstream endpoint
			// so multi-WAN route changes are reflected without process restart.
			bindIP = dynamicIP
		}
		// Only meaningful in legacy route-bound mode (InterfaceName==""). When we
		// pin to a device (INTERFACE/auto), the route IP legitimately differs
		// from our bound WAN IP (e.g. a VPN tun owns the default route), so this
		// would false-positive — WAN changes are handled by the wan-watcher.
		if s.Injector != nil && s.InterfaceName == "" && s.InterfaceIP != "" && strings.TrimSpace(dynamicIP) != "" && dynamicIP != s.InterfaceIP {
			logx.Warnf("raw injector route-change detected old_local_ip=%s new_local_ip=%s endpoint=%s; restart service to rebind injector", s.InterfaceIP, dynamicIP, selected.IP)
		}

		var laddr *net.TCPAddr
		if bindIP != "" {
			laddr = &net.TCPAddr{IP: net.ParseIP(bindIP)}
		}

		if s.Injector != nil {
			// Reserve a port and register it with the injector. If two
			// goroutines race to the same ephemeral port (the kernel can
			// hand the same value back briefly after release), RegisterPort
			// returns false instead of clobbering an in-flight flow's
			// confirmation state. Bounded retries (3) keep this from spinning
			// under pathological churn.
			const maxReserveRetries = 3
			reserved := false
			var reservedPort int
			for r := 0; r < maxReserveRetries; r++ {
				p, reserveErr := reserveTCPPort(laddr)
				if reserveErr != nil {
					break
				}
				hello, decoy := s.fakeHelloFor(selected.SNI)
				if !s.Injector.RegisterPort(p, hello) {
					// Collision: another flow already owns this port. Try again.
					continue
				}
				reservedPort = p
				reservedDecoy = decoy
				reserved = true
				break
			}
			if !reserved {
				logx.Warnf("port reservation failed after %d attempts endpoint=%s:%d", maxReserveRetries, selected.IP, selected.Port)
				continue
			}
			if laddr == nil {
				laddr = &net.TCPAddr{IP: net.IPv4zero, Port: reservedPort}
			} else {
				laddr = &net.TCPAddr{IP: laddr.IP, Port: reservedPort}
			}
			registeredPort = reservedPort
			registered = true
		}

		// Bind the upstream dial to the WAN device when INTERFACE is set, so the
		// real data connection leaves via the physical NIC instead of a VPN tun
		// that owns the default route (native equivalent of VpnService.protect).
		dialer := net.Dialer{}
		if laddr != nil {
			dialer.LocalAddr = laddr
		}
		if ctrl := netutil.BindToDeviceControl(s.InterfaceName); ctrl != nil {
			dialer.Control = ctrl
		}
		var conn net.Conn
		conn, err = dialer.DialContext(ctx, "tcp4", raddr.String())
		if err == nil {
			outgoing, _ = conn.(*net.TCPConn)
		}
		if err == nil {
			applyOK := s.Strategy.Apply(ctx, incoming, outgoing, selected.SNI, first)
			if reservedDecoy != "" {
				s.decoys.record(reservedDecoy, applyOK)
			}
			if applyOK {
				break
			}

			if s.Strategy.Name() == "wrong_seq" {
				diag := strings.TrimSpace(rawinjector.RawDiagnostic())
				if diag != "" {
					lastStrategyErr = fmt.Errorf("wrong_seq confirmation failed: %s", diag)
				} else {
					lastStrategyErr = fmt.Errorf("wrong_seq confirmation failed")
				}
			} else {
				lastStrategyErr = fmt.Errorf("strategy apply returned false: %s", s.Strategy.Name())
			}

			if attempt+1 < totalAttempts {
				logx.Warnf("strategy apply failed endpoint=%s:%d strategy=%s attempt=%d/%d err=%v; trying next endpoint", selected.IP, selected.Port, s.Strategy.Name(), attempt+1, totalAttempts, lastStrategyErr)
				if registered {
					s.Injector.CleanupPort(registeredPort)
					registered = false
					registeredPort = 0
				}
				_ = outgoing.Close()
				outgoing = nil
				continue
			}

			if registered {
				s.Injector.CleanupPort(registeredPort)
				registered = false
				registeredPort = 0
			}

			if s.Strategy.Name() == "wrong_seq" {
				logx.Warnf("connection dropped before upstream first-write: strategy=wrong_seq request_sni=%q endpoint=%s:%d reason=strategy_apply_failed err=%v", requestSNI, selected.IP, selected.Port, lastStrategyErr)
				_ = outgoing.Close()
				return
			}

			logx.Warnf("strategy apply returned false: strategy=%s request_sni=%q endpoint=%s:%d; falling back to direct first-write", s.Strategy.Name(), requestSNI, selected.IP, selected.Port)
			_, _ = outgoing.Write(first)
			break
		}
		lastConnectErr = err
		logx.Warnf("upstream dial failed endpoint=%s:%d local_ip=%s attempt=%d/%d err=%v", selected.IP, selected.Port, bindIP, attempt+1, totalAttempts, err)
		if registered {
			s.Injector.CleanupPort(registeredPort)
			registered = false
			registeredPort = 0
		}
	}
	if outgoing == nil {
		if lastStrategyErr != nil {
			logx.Warnf("connection dropped before bypass: request_sni=%q reason=all_endpoints_failed_confirmation last_connect_error=%v last_strategy_error=%v action=core_restart_recommended", requestSNI, lastConnectErr, lastStrategyErr)
			s.reportFailure("all_endpoints_failed_confirmation")
		} else {
			logx.Warnf("connection dropped before bypass: request_sni=%q reason=upstream_unreachable last_error=%v action=core_restart_recommended", requestSNI, lastConnectErr)
			s.reportFailure("upstream_unreachable")
		}
		return
	}
	s.reportSuccess()
	defer outgoing.Close()
	_ = outgoing.SetKeepAlive(true)
	_ = outgoing.SetKeepAlivePeriod(60 * time.Second)
	logx.Debugf("selected endpoint ip=%s port=%d sni=%s", selected.IP, selected.Port, selected.SNI)

	// Count relayed bytes for throughput stats. up = client→upstream (incoming
	// read), down = upstream→client (outgoing read). No-op when Counters is nil.
	// The first client segment (the ClientHello) was already sent upstream by the
	// bypass, before the relay loop, so add it to Up here or it would be missed.
	var upSrc, downSrc io.Reader = incoming, outgoing
	if s.Counters != nil {
		s.Counters.Up.Add(uint64(len(first)))
		upSrc = &countingReader{incoming, &s.Counters.Up}
		downSrc = &countingReader{outgoing, &s.Counters.Down}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, copyErr := io.Copy(outgoing, upSrc); copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, net.ErrClosed) {
			logx.Debugf("stream copy incoming->outgoing ended with error: %v", copyErr)
		}
		_ = outgoing.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		if _, copyErr := io.Copy(incoming, downSrc); copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, net.ErrClosed) {
			logx.Debugf("stream copy outgoing->incoming ended with error: %v", copyErr)
		}
		_ = incoming.CloseWrite()
	}()
	wg.Wait()
}

func (s *Server) reportSuccess() {
	s.failureStreak.Store(0)
	s.restartSent.Store(false)
}

func (s *Server) reportFailure(reason string) {
	threshold := s.CriticalFailures
	if threshold <= 0 {
		threshold = 12
	}
	streak := s.failureStreak.Add(1)
	if int(streak) < threshold {
		return
	}
	if s.OnCriticalError == nil {
		return
	}
	if !s.restartSent.CompareAndSwap(false, true) {
		return
	}
	logx.Warnf("critical recovery threshold reached listener=%s:%d streak=%d threshold=%d reason=%s action=core_internal_restart", s.ListenHost, s.ListenPort, streak, threshold, reason)
	s.OnCriticalError(reason)
}

func (s *Server) endpointsOrDefault() []config.Endpoint {
	if len(s.Endpoints) > 0 {
		return s.Endpoints
	}
	return []config.Endpoint{{IP: s.ConnectIP, Port: s.ConnectPort, SNI: s.FakeSNI, Enabled: true}}
}

func (s *Server) pickBaseIndex(total int) int {
	if total <= 1 {
		return 0
	}
	switch s.LoadBalance {
	case "", "failover":
		return 0
	case "round_robin":
		return int(s.lbCounter.Add(1)-1) % total
	case "random":
		return rand.Intn(total)
	default:
		return 0
	}
}

func reserveTCPPort(laddr *net.TCPAddr) (int, error) {
	bindIP := net.IPv4zero
	if laddr != nil && laddr.IP != nil {
		bindIP = laddr.IP
	}
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: bindIP, Port: 0})
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

// fakeHelloFor builds the decoy ClientHello for one wrong_seq connection,
// rotating the decoy SNI and/or fingerprint across the configured pools so a DPI
// can't pin a single decoy/fingerprint over time. baseSNI is the endpoint's
// decoy; pools are opt-in (empty = no rotation). The fake must fit one segment,
// so an oversized rotated combo falls back to the base SNI + default fingerprint.
// It returns the chosen decoy SNI (empty when none was rotated in, i.e. the base
// decoy was used or a too-large combo fell back) so the caller can attribute the
// connection's confirm/fail outcome back to that decoy via decoyPool.record.
func (s *Server) fakeHelloFor(baseSNI string) (hello []byte, decoy string) {
	s.decoysOnce.Do(func() {
		if len(s.FakeSNIPool) > 0 {
			s.decoys = newDecoyPool(s.FakeSNIPool)
		}
	})
	sni := baseSNI
	if v := s.decoys.pick(); v != "" {
		sni = v
		decoy = v
	}
	fp := tlsutil.Fingerprint()
	if n := len(s.UTLSPool); n > 0 {
		fp = strings.TrimSpace(s.UTLSPool[rand.Intn(n)])
	}
	hello = tlsutil.BuildClientHelloFP(sni, fp)
	if len(hello) > config.MaxFakeHelloBytes {
		hello = tlsutil.BuildClientHelloFP(baseSNI, tlsutil.Fingerprint())
		logx.Debugf("fake hello rotated combo too large; fell back base_sni=%q size=%d", baseSNI, len(hello))
		decoy = "" // used the base decoy, not the rotated one — don't attribute to it
	}
	if s.decoys != nil || len(s.UTLSPool) > 0 {
		logx.Debugf("fake hello decoy_sni=%q fp=%q size=%d", sni, fp, len(hello))
	}
	return hello, decoy
}
