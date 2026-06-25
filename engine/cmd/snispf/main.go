package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"runtime"
	"snispf/internal/bypass"
	"snispf/internal/config"
	"snispf/internal/forwarder"
	"snispf/internal/logx"
	"snispf/internal/matrix"
	"snispf/internal/netutil"
	"snispf/internal/platform"
	"snispf/internal/rawinjector"
	"snispf/internal/scan"
	"snispf/internal/service"
	"snispf/internal/tlsutil"
)

var version = "1.1.0-go"

const apiVersion = "v1"

const banner = `
 SNISPF - Cross-Platform DPI Bypass Tool
 SNI Spoofing + TLS Fragmentation
`

func main() {
	os.Args = append([]string{os.Args[0]}, normalizeCLIArgs(os.Args[1:])...)

	var (
		configPath       = flag.String("config", "", "Path to JSON config file")
		configPathShort  = flag.String("C", "", "Path to JSON config file")
		generateConfig   = flag.String("generate-config", "", "Generate default config and exit")
		configDoctor     = flag.Bool("config-doctor", false, "Validate config and print recommendations")
		runCore          = flag.Bool("run-core", false, "Internal: run proxy core mode")
		serviceMode      = flag.Bool("service", false, "Run localhost control service API")
		serviceAddr      = flag.String("service-addr", "127.0.0.1:8797", "Control service listen address")
		serviceToken     = flag.String("service-token", "", "Control service auth token (optional)")
		serviceParentPID = flag.Int("service-parent-pid", 0, "Internal: parent process ID to monitor")
		serviceParentTS  = flag.Int64("service-parent-start-unix-ms", 0, "Internal: parent process start time (unix ms) for robust monitoring")
		showBuildInfo    = flag.Bool("build-info", false, "Show core build/runtime metadata")
		listen           = flag.String("listen", "", "Listen address HOST:PORT")
		listenShort      = flag.String("l", "", "Listen address HOST:PORT")
		connect          = flag.String("connect", "", "Target address IP:PORT")
		connectShort     = flag.String("c", "", "Target address IP:PORT")
		sni              = flag.String("sni", "", "Fake SNI hostname")
		sniShort         = flag.String("s", "", "Fake SNI hostname")
		method           = flag.String("method", "", "Bypass method: fragment|fake_sni|combined|wrong_seq")
		methodShort      = flag.String("m", "", "Bypass method: fragment|fake_sni|combined|wrong_seq")
		fragmentStrategy = flag.String("fragment-strategy", "", "Fragment strategy")
		fragmentDelay    = flag.Float64("fragment-delay", -1, "Delay between fragments")
		ttlTrick         = flag.Bool("ttl-trick", false, "Enable TTL trick")
		noRaw            = flag.Bool("no-raw", false, "Disable raw injection")
		verbose          = flag.Bool("verbose", false, "Verbose output")
		verboseShort     = flag.Bool("v", false, "Verbose output")
		quiet            = flag.Bool("quiet", false, "Quiet output")
		quietShort       = flag.Bool("q", false, "Quiet output")
		showInfo         = flag.Bool("info", false, "Show platform capabilities")
		showVersion      = flag.Bool("version", false, "Show version")
		showVersionShort = flag.Bool("V", false, "Show version")
		scanMode         = flag.Bool("scan", false, "Scan Cloudflare IPs directly (no DNS) for reachable edges, rank by RTT")
		scanApply        = flag.Bool("scan-apply", false, "With --scan: write the best IP into the config (CONNECT_IP/FAKE_SNI)")
		scanHits         = flag.String("scan-hits", "", "Hit-list JSON path for --scan (persists proven survivors)")
		scanHitsOnly     = flag.Bool("scan-hits-only", false, "With --scan: probe only stored hit-list survivors (fast)")
		scanSNI          = flag.String("scan-sni", scan.DefaultProbeSNI, "Probe SNI for --scan (DPI-allowed CF host)")
		scanPerRange     = flag.Int("scan-per-range", 16, "IPs sampled per Cloudflare range for --scan")
		scanThreads      = flag.Int("scan-threads", 40, "Concurrency for --scan")
		testMode         = flag.Bool("test", false, "Auto-tune: try uTLS×method combos through a temp tunnel, report PASS/FAIL")
		testApply        = flag.Bool("test-apply", false, "With --test: write the best passing uTLS+method into the config")
	)
	flag.Parse()

	if *showVersion || *showVersionShort {
		fmt.Println("SNISPF", version)
		return
	}

	if *showBuildInfo {
		fmt.Printf("version=%s\n", version)
		fmt.Printf("api_version=%s\n", apiVersion)
		fmt.Printf("goos=%s\n", runtime.GOOS)
		fmt.Printf("goarch=%s\n", runtime.GOARCH)
		return
	}

	_ = runCore // accepted for compatibility with service-spawned children; no behavioural effect.

	if *showInfo {
		fmt.Print(banner)
		caps := platform.CheckCapabilities(rawinjector.IsRawAvailable())
		fmt.Printf("platform=%s\n", caps.Platform)
		fmt.Printf("fragment_support=%v\n", caps.Fragment)
		fmt.Printf("tls_record_frag=%v\n", caps.TLSRecordFrag)
		fmt.Printf("fake_sni=%v\n", caps.FakeSNI)
		fmt.Printf("tcp_nodelay=%v\n", caps.TCPNoDelay)
		fmt.Printf("raw_socket=%v\n", caps.RawSocket)
		fmt.Printf("ip_ttl_trick=%v\n", caps.IPTTLTrick)
		fmt.Printf("af_packet=%v\n", caps.AFPacket)
		fmt.Printf("raw_injection=%v\n", caps.RawInjection)
		if diag := strings.TrimSpace(rawinjector.RawDiagnostic()); diag != "" {
			fmt.Printf("raw_injection_diagnostic=%s\n", diag)
		}
		printPrivilegeGuidance(caps)
		return
	}

	cfgPath := firstNonEmpty(*configPath, *configPathShort)
	if cfgPath == "" {
		cfgPath = "config.json"
	}

	if *scanMode {
		runScan(cfgPath, scan.Options{
			PerRange: *scanPerRange, SNI: *scanSNI, Threads: *scanThreads,
			HitsPath: *scanHits, HitsOnly: *scanHitsOnly, Save: *scanHits != "",
		}, *scanApply)
		return
	}

	if *testMode {
		runTest(cfgPath, *testApply)
		return
	}

	if *serviceMode {
		cfgForLogs, _ := config.LoadOrDefault(cfgPath)
		config.Normalize(&cfgForLogs)
		configureLogger(cfgForLogs.LogLevel, *quiet || *quietShort, *verbose || *verboseShort)

		tok := strings.TrimSpace(*serviceToken)
		if tok == "" {
			tok = strings.TrimSpace(os.Getenv("SNISPF_SERVICE_TOKEN"))
		}
		if err := service.Run(cfgPath, *serviceAddr, tok, *serviceParentPID, *serviceParentTS, apiVersion); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *generateConfig != "" {
		if err := config.Write(*generateConfig, config.DefaultConfig); err != nil {
			log.Fatalf("failed to write config: %v", err)
		}
		fmt.Println("Generated config:", *generateConfig)
		return
	}

	cfg := config.DefaultConfig
	if cfgPath != "" {
		loaded, err := config.Load(cfgPath)
		if err != nil {
			log.Fatal(err)
		}
		cfg = loaded
	}

	if v := firstNonEmpty(*listen, *listenShort); v != "" {
		host, port, err := netutil.ParseHostPort(v, "0.0.0.0", 40443)
		if err != nil {
			log.Fatal(err)
		}
		cfg.ListenHost, cfg.ListenPort = host, port
	}
	if v := firstNonEmpty(*connect, *connectShort); v != "" {
		host, port, err := netutil.ParseHostPort(v, "188.114.98.0", 443)
		if err != nil {
			log.Fatal(err)
		}
		cfg.ConnectIP, cfg.ConnectPort = host, port
	}
	if v := firstNonEmpty(*sni, *sniShort); v != "" {
		cfg.FakeSNI = v
	}
	if v := firstNonEmpty(*method, *methodShort); v != "" {
		cfg.BypassMethod = strings.ToLower(v)
	}
	if *fragmentStrategy != "" {
		cfg.FragmentStrategy = *fragmentStrategy
	}
	if *fragmentDelay >= 0 {
		cfg.FragmentDelay = *fragmentDelay
	}
	if *ttlTrick {
		cfg.UseTTLTrick = true
	}

	if !netutil.IsValidPort(cfg.ListenPort) || !netutil.IsValidPort(cfg.ConnectPort) {
		log.Fatal("invalid listen/connect port")
	}

	cfgBeforeNormalize := cfg
	config.Normalize(&cfg)
	tlsutil.SetFingerprint(cfg.UTLS) // real-browser fake ClientHello when set
	precedenceWarnings := config.PrecedenceWarnings(cfgBeforeNormalize)
	activeEndpoints := config.EnabledEndpoints(cfg.Endpoints)
	if len(activeEndpoints) == 0 {
		log.Fatal("no valid enabled endpoints in config")
	}
	if cfg.EndpointProbe {
		activeEndpoints = config.ProbeHealthyEndpoints(
			activeEndpoints,
			time.Duration(cfg.ProbeTimeoutMS)*time.Millisecond,
		)
	}
	cfg.Endpoints = activeEndpoints

	if cfg.BypassMethod != "fragment" && cfg.BypassMethod != "fake_sni" && cfg.BypassMethod != "combined" && cfg.BypassMethod != "wrong_seq" {
		logx.Warnf("unknown bypass method %q, using fragment", cfg.BypassMethod)
		cfg.BypassMethod = "fragment"
	}

	if err := config.ValidateSNIGuardrails(cfg); err != nil {
		log.Fatal(err)
	}

	if *configDoctor {
		caps := platform.CheckCapabilities(rawinjector.IsRawAvailable())
		issues, warnings := config.RunDoctor(cfg, caps)
		if len(issues) == 0 {
			fmt.Println("config-doctor: OK")
		} else {
			fmt.Println("config-doctor: issues found")
			for _, issue := range issues {
				fmt.Printf("- ERROR: %s\n", issue)
			}
		}
		for _, warning := range warnings {
			fmt.Printf("- WARN: %s\n", warning)
		}
		printPrivilegeGuidance(caps)
		if len(issues) > 0 {
			os.Exit(1)
		}
		return
	}

	configureLogger(cfg.LogLevel, *quiet || *quietShort, *verbose || *verboseShort)
	for _, warning := range precedenceWarnings {
		logx.Warnf("%s", warning)
	}

	restartReqCh := make(chan string, 1)
	onCriticalRestart := func(reason string) {
		select {
		case restartReqCh <- reason:
		default:
		}
	}

	runtimes, err := buildServerRuntimes(cfg, *noRaw, onCriticalRestart)
	if err != nil {
		log.Fatal(err)
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Print(banner)
	logx.Infof("SNISPF Go | strategy=%s | listeners=%d", cfg.FragmentStrategy, len(runtimes))
	logx.Infof("platform=%s", runtime.GOOS)

	for i := range runtimes {
		rt := runtimes[i]
		printRuntimeModeHint(rt.cfg, rt.injector != nil)
	}

	// Resilience: rebind automatically when the physical WAN changes (antenna
	// reconnect, mobile rmnet rotation, Wi-Fi handover) instead of silently
	// breaking new connections. The listener/daemon stay up throughout.
	if strings.TrimSpace(cfg.Interface) != "" {
		go watchWAN(rootCtx, cfg.Interface, cfg.ConnectIP, onCriticalRestart)
	}

	lastRestartAt := time.Time{}
	restartBurst := 0

	for {
		runCtx, cancelRun := context.WithCancel(rootCtx)
		errCh := make(chan error, len(runtimes))

		for i := range runtimes {
			rt := runtimes[i]
			go func(name string, srv *forwarder.Server) {
				if runErr := srv.Run(runCtx); runErr != nil && !errors.Is(runErr, context.Canceled) {
					errCh <- fmt.Errorf("listener %s failed: %w", name, runErr)
				}
			}(rt.name, rt.server)
		}

		select {
		case <-rootCtx.Done():
			cancelRun()
			for i := range runtimes {
				if runtimes[i].injector != nil {
					runtimes[i].injector.Stop()
				}
			}
			return
		case runErr := <-errCh:
			cancelRun()
			for i := range runtimes {
				if runtimes[i].injector != nil {
					runtimes[i].injector.Stop()
				}
			}
			log.Fatal(runErr)
		case reason := <-restartReqCh:
			now := time.Now()
			if !lastRestartAt.IsZero() && now.Sub(lastRestartAt) < 20*time.Second {
				restartBurst++
			} else {
				restartBurst = 1
			}
			lastRestartAt = now
			if restartBurst > 3 {
				cancelRun()
				for i := range runtimes {
					if runtimes[i].injector != nil {
						runtimes[i].injector.Stop()
					}
				}
				log.Fatalf("internal recovery aborted: repeated restart loop detected reason=%s", reason)
			}

			logx.Warnf("internal recovery requested reason=%s action=rebuild_runtimes burst=%d", reason, restartBurst)
			cancelRun()
			for i := range runtimes {
				if runtimes[i].injector != nil {
					runtimes[i].injector.Stop()
				}
			}

			runtimes, err = buildServerRuntimes(cfg, *noRaw, onCriticalRestart)
			if err != nil {
				log.Fatal(err)
			}
			for i := range runtimes {
				rt := runtimes[i]
				printRuntimeModeHint(rt.cfg, rt.injector != nil)
			}
		}
	}
}

// watchWAN triggers a runtime rebuild when the physical WAN device or its IP
// changes, so the raw injector + dial rebind to the live interface. Debounced
// (new value must persist two ticks) to ride out brief flaps and stay clear of
// the restart-burst guard.
func watchWAN(ctx context.Context, ifaceCfg, probeIP string, onCritical func(string)) {
	resolve := func() (string, string) {
		name := strings.TrimSpace(ifaceCfg)
		if strings.EqualFold(name, "auto") {
			name = netutil.PhysicalWANInterface(probeIP)
		}
		return name, netutil.InterfaceIPv4(name)
	}
	lastName, lastIP := resolve()
	var candName, candIP string
	candCount := 0
	t := time.NewTicker(6 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			name, ip := resolve()
			if name == "" || ip == "" {
				// No usable WAN right now — auto found none, or a forced interface
				// is down. WAIT for it to come back instead of rebinding to a dead
				// interface (and never switch away from a forced one).
				candCount = 0
				continue
			}
			if name == lastName && ip == lastIP {
				candCount = 0
				continue
			}
			if name == candName && ip == candIP {
				candCount++
			} else {
				candName, candIP, candCount = name, ip, 1
			}
			if candCount >= 2 {
				logx.Warnf("WAN change %s/%s -> %s/%s; rebinding injector", lastName, lastIP, name, ip)
				lastName, lastIP, candCount = name, ip, 0
				onCritical("wan_changed")
			}
		}
	}
}

func buildStrategy(cfg config.Config, method string, injector rawinjector.Interface) bypass.Strategy {
	switch strings.ToLower(method) {
	case "fake_sni":
		return bypass.NewFakeSNI(cfg.FakeSNIMethod, cfg.FragmentDelay, time.Duration(cfg.WrongSeqConfirmTimeoutMS)*time.Millisecond, injector)
	case "combined":
		return bypass.NewCombined(cfg.FragmentStrategy, cfg.FragmentDelay, cfg.UseTTLTrick, time.Duration(cfg.WrongSeqConfirmTimeoutMS)*time.Millisecond, injector)
	case "wrong_seq":
		return bypass.NewWrongSeqStrict(injector, time.Duration(cfg.WrongSeqConfirmTimeoutMS)*time.Millisecond)
	default:
		return bypass.NewFragment(cfg.FragmentStrategy, cfg.FragmentDelay)
	}
}

type serverRuntime struct {
	name     string
	cfg      config.Config
	server   *forwarder.Server
	injector rawinjector.Interface
}

func buildServerRuntimes(cfg config.Config, noRaw bool, onCritical func(reason string)) ([]serverRuntime, error) {
	if len(cfg.Listeners) == 0 {
		// Endpoints are already probed at the top level; skip inner probe.
		rt, err := buildSingleRuntime(cfg, noRaw, true, "primary", cfg.ListenHost, cfg.ListenPort, cfg.Endpoints, cfg.BypassMethod, onCritical)
		if err != nil {
			return nil, err
		}
		return []serverRuntime{rt}, nil
	}

	runtimes := make([]serverRuntime, 0, len(cfg.Listeners))
	for i, ls := range cfg.Listeners {
		name := ls.Name
		if strings.TrimSpace(name) == "" {
			name = fmt.Sprintf("listener-%d", i+1)
		}
		endpoints := []config.Endpoint{{
			Name:    name + "-upstream",
			IP:      netutil.ResolveHost(ls.ConnectIP),
			Port:    ls.ConnectPort,
			SNI:     ls.FakeSNI,
			Enabled: true,
		}}
		method := strings.TrimSpace(ls.BypassMethod)
		if method == "" {
			method = cfg.BypassMethod
		}

		rt, err := buildSingleRuntime(cfg, noRaw, false, name, ls.ListenHost, ls.ListenPort, endpoints, method, onCritical)
		if err != nil {
			return nil, err
		}
		runtimes = append(runtimes, rt)
	}
	return runtimes, nil
}

func buildSingleRuntime(baseCfg config.Config, noRaw bool, probeAlreadyDone bool, name, listenHost string, listenPort int, endpoints []config.Endpoint, method string, onCritical func(reason string)) (serverRuntime, error) {
	cfg := baseCfg
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		method = "fragment"
	}
	if method != "fragment" && method != "fake_sni" && method != "combined" && method != "wrong_seq" {
		logx.Warnf("unknown bypass method %q for %s, using fragment", method, name)
		method = "fragment"
	}

	if cfg.EndpointProbe && !probeAlreadyDone {
		endpoints = config.ProbeHealthyEndpoints(endpoints, time.Duration(cfg.ProbeTimeoutMS)*time.Millisecond)
	}
	if len(endpoints) == 0 {
		return serverRuntime{}, fmt.Errorf("%s has no available endpoint", name)
	}

	// Resolve the egress interface. "auto" probes the physical WAN so the whole
	// flow (real dial + fake injection) leaves the physical NIC and escapes a
	// VPN tun — without this, a FULL-TUNNEL VPN owns the default route, so
	// route-based detection binds to the tun and the bypass operates on
	// already-tunneled traffic (works only when the VPN is per-app/excludes us).
	ifName := strings.TrimSpace(cfg.Interface)
	if strings.EqualFold(ifName, "auto") {
		ifName = netutil.PhysicalWANInterface(endpoints[0].IP)
		if ifName != "" {
			logx.Infof("%s: auto-selected WAN interface %s (escapes VPN tun)", name, ifName)
		} else {
			logx.Warnf("%s: INTERFACE=auto found no physical WAN; falling back to route default", name)
		}
	}
	var interfaceIP string
	if ifName != "" {
		interfaceIP = netutil.InterfaceIPv4(ifName)
	}
	if interfaceIP == "" {
		interfaceIP = netutil.GetDefaultInterfaceIPv4(endpoints[0].IP)
	}

	var injector rawinjector.Interface
	if len(endpoints) == 1 && !noRaw && (method == "fake_sni" || method == "combined" || method == "wrong_seq") && rawinjector.IsRawAvailable() {
		injector = rawinjector.New(interfaceIP, endpoints[0].IP, endpoints[0].Port, tlsutil.BuildClientHello)
		// Pin the injector to the resolved interface so fake packets inject on
		// the same physical NIC the real dial uses.
		if ifName != "" {
			if setter, ok := injector.(rawinjector.InterfaceNameSetter); ok {
				setter.SetInterfaceName(ifName)
			}
		}
		if !injector.Start() {
			injector = nil
			logx.Warnf("raw injector unavailable at runtime for %s, falling back", name)
		}
	}

	if method == "wrong_seq" {
		if len(endpoints) != 1 {
			return serverRuntime{}, fmt.Errorf("%s: wrong_seq requires exactly one enabled endpoint", name)
		}
		if injector == nil {
			diag := strings.TrimSpace(rawinjector.RawDiagnostic())
			if diag == "" {
				return serverRuntime{}, fmt.Errorf("%s: wrong_seq requires raw injector support; use Linux (CAP_NET_RAW/root) or Windows (Administrator + WinDivert)", name)
			}
			return serverRuntime{}, fmt.Errorf("%s: wrong_seq requires raw injector support; use Linux (CAP_NET_RAW/root) or Windows (Administrator + WinDivert). detail: %s", name, diag)
		}
	}

	cfg.ListenHost = listenHost
	cfg.ListenPort = listenPort
	cfg.ConnectIP = endpoints[0].IP
	cfg.ConnectPort = endpoints[0].Port
	cfg.FakeSNI = endpoints[0].SNI
	cfg.Endpoints = endpoints
	cfg.BypassMethod = method

	strategy := buildStrategy(cfg, method, injector)
	srv := &forwarder.Server{
		ListenHost:      listenHost,
		ListenPort:      listenPort,
		ConnectIP:       endpoints[0].IP,
		ConnectPort:     endpoints[0].Port,
		FakeSNI:         endpoints[0].SNI,
		Endpoints:       endpoints,
		LoadBalance:     cfg.LoadBalance,
		AutoFailover:    cfg.AutoFailover,
		FailoverRetries: cfg.FailoverRetries,
		FakeSNIPool:     cfg.FakeSNIPool,
		UTLSPool:        cfg.UTLSPool,
		InterfaceIP:     interfaceIP,
		InterfaceName:   ifName,
		Strategy:        strategy,
		Injector:        injector,
		OnCriticalError: onCritical,
	}
	if len(endpoints) > 1 && strings.TrimSpace(cfg.LoadBalance) != "" {
		srv.CriticalFailures = 8
	} else {
		srv.CriticalFailures = 20
	}

	return serverRuntime{name: name, cfg: cfg, server: srv, injector: injector}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func runTest(cfgPath string, apply bool) {
	cfg, err := config.LoadOrDefault(cfgPath)
	if err != nil {
		log.Fatalf("test: load %s: %v", cfgPath, err)
	}
	config.Normalize(&cfg)
	exe, _ := os.Executable()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("auto-tune through %s:%d (decoy %s)...\n\n", cfg.ConnectIP, cfg.ConnectPort, cfg.FakeSNI)
	results, err := matrix.Run(ctx, matrix.Options{ExePath: exe, Base: cfg})
	if err != nil {
		log.Fatalf("test: %v", err)
	}
	var best *matrix.Result
	for i, r := range results {
		st, extra := "FAIL", r.Err
		if r.Pass {
			st, extra = "PASS", fmt.Sprintf("%dms", r.LatencyMS)
			if best == nil {
				best = &results[i]
			}
		}
		fmt.Printf("  %-4s  utls=%-8s method=%-9s  %s\n", st, r.Case.UTLS, r.Case.Method, extra)
	}
	if best == nil {
		fmt.Println("\nno combo passed — try a different CONNECT_IP / FAKE_SNI (run --scan)")
		return
	}
	fmt.Printf("\nBEST: utls=%s method=%s (%dms)\n", best.Case.UTLS, best.Case.Method, best.LatencyMS)
	if !apply {
		return
	}
	cfg.UTLS = best.Case.UTLS
	cfg.BypassMethod = best.Case.Method
	if err := config.Write(cfgPath, cfg); err != nil {
		log.Fatalf("test-apply: write %s: %v", cfgPath, err)
	}
	fmt.Printf("applied to %s: UTLS=%s BYPASS_METHOD=%s\n", cfgPath, best.Case.UTLS, best.Case.Method)
}

func runScan(cfgPath string, opts scan.Options, apply bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if opts.Interface == "" {
		if cfg, err := config.LoadOrDefault(cfgPath); err == nil {
			config.Normalize(&cfg)
			opts.Interface = netutil.ResolveWAN(cfg.Interface, cfg.ConnectIP)
		}
	}
	rep, err := scan.Run(ctx, opts)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	fmt.Printf("clean %d | dpi-blocked %d | tcp-blocked %d | probed %d\n\n",
		rep.Clean, rep.DPIBlocked, rep.TCPBlocked, rep.Probed)
	n := len(rep.Results)
	if n > 15 {
		n = 15
	}
	for i, r := range rep.Results[:n] {
		mark := " "
		if i == 0 {
			mark = "*"
		} else if r.Known {
			mark = "+"
		}
		fmt.Printf("%s %2d  %-15s  %6.0fms  %-5s  seen %d/%d\n",
			mark, i+1, r.IP, r.RTTMS, r.Status, r.Clean, r.Seen)
	}
	if rep.Best == nil {
		fmt.Println("\nno reachable edge found")
		return
	}
	b := rep.Best
	fmt.Printf("\nBEST: -connect %s:443 -sni %s  (%.0fms)\n", b.IP, opts.SNI, b.RTTMS)
	if !apply {
		return
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("scan-apply: load %s: %v", cfgPath, err)
	}
	cfg.ConnectIP = b.IP
	cfg.ConnectPort = 443
	cfg.FakeSNI = opts.SNI
	if err := config.Write(cfgPath, cfg); err != nil {
		log.Fatalf("scan-apply: write %s: %v", cfgPath, err)
	}
	fmt.Printf("applied to %s: CONNECT_IP=%s FAKE_SNI=%s\n", cfgPath, b.IP, opts.SNI)
}

func printPrivilegeGuidance(caps platform.Capabilities) {
	if caps.RawInjection {
		fmt.Println("privilege-note: elevated privileges detected for raw injection mode")
		return
	}
	fmt.Println("privilege-note: admin/root is NOT always required; fragment mode works unprivileged")
	if !caps.RawInjection {
		fmt.Println("privilege-note: fake_sni/combined may use fallback behavior without elevated privileges")
	}
}

func printRuntimeModeHint(cfg config.Config, rawActive bool) {
	if rawActive {
		logx.Infof("runtime: raw injection active")
		return
	}
	if cfg.BypassMethod == "fragment" {
		logx.Infof("runtime: unprivileged fragment mode")
		return
	}
	logx.Infof("runtime: fallback mode (raw injection not active)")
}

func configureLogger(configLevel string, quiet, verbose bool) {
	levelText := strings.ToLower(strings.TrimSpace(configLevel))
	if levelText == "" {
		levelText = "info"
	}

	if verbose {
		levelText = "debug"
	}
	if quiet {
		levelText = "error"
	}

	if err := logx.SetLevelString(levelText); err != nil {
		_ = logx.SetLevelString("info")
		logx.Warnf("invalid LOG_LEVEL %q, using info", configLevel)
	}

	if verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		return
	}
	log.SetFlags(log.LstdFlags)
}

func normalizeCLIArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	rest := args[1:]

	switch cmd {
	case "run":
		return rest
	case "service":
		return append([]string{"--service"}, rest...)
	case "doctor":
		return append([]string{"--config-doctor"}, rest...)
	case "build-info":
		return append([]string{"--build-info"}, rest...)
	default:
		return args
	}
}
