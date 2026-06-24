package service

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"snispf/internal/config"
	"snispf/internal/logx"
	"snispf/internal/matrix"
	"snispf/internal/netutil"
	"snispf/internal/platform"
	"snispf/internal/rawinjector"
	"snispf/internal/scan"
)

type controlService struct {
	mu         sync.Mutex
	cfgPath    string
	token      string
	exePath    string
	child      *exec.Cmd
	childLog   *os.File
	startedAt  time.Time
	lastError  string
	logPath    string
	starting   bool
	apiVersion string

	// async scan job (so the WebUI never blocks on a long scan call)
	scanMu  sync.Mutex
	scanRun bool
	scanDone bool
	scanRep *scan.Report
	scanErr string

	// async auto-tune job (matrix can run ~2 min — never block the WebUI on it)
	testMu      sync.Mutex
	testRun     bool
	testDone    bool
	testResults []matrix.Result
	testBest    *matrix.Result
	testErr     string
}

type serviceStatus struct {
	APIVersion            string    `json:"api_version"`
	Running               bool      `json:"running"`
	PID                   int       `json:"pid,omitempty"`
	StartedAt             time.Time `json:"started_at,omitempty"`
	LastError             string    `json:"last_error,omitempty"`
	LogPath               string    `json:"log_path"`
	ConfigPath            string    `json:"config_path"`
	Platform              string    `json:"platform"`
	Architecture          string    `json:"architecture"`
	RawInjectionAvailable bool      `json:"raw_injection_available"`
	RawDiagnostic         string    `json:"raw_diagnostic,omitempty"`
}

type healthEndpoint struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	SNI       string `json:"sni"`
	Healthy   bool   `json:"healthy"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

type wrongSeqHealthStats struct {
	Confirmed      int `json:"confirmed"`
	Timeout        int `json:"timeout"`
	Failed         int `json:"failed"`
	NotRegistered  int `json:"not_registered"`
	FirstWriteFail int `json:"first_write_fail"`
	SourceLines    int `json:"source_lines"`
}

// Run starts the HTTP control service that manages the proxy core process.
func Run(cfgPath, addr, token string, parentPID int, parentStartUnixMS int64, apiVersion string) error {
	ignoreHangup() // survive the boot-service shell exiting (Magisk SIGHUP)

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// A missing API log file must never take the daemon down — the boot
	// service already redirects our stdout/stderr to /data/adb/snispf/service.log,
	// so we degrade to stdout-only instead of dying.
	logPath, err := serviceLogPath(cfgPath)
	if err != nil {
		log.Printf("service log file unavailable, logging to stdout only: %v", err)
		logPath = ""
	} else if err := ensureLogSink(logPath); err != nil {
		log.Printf("could not open service log %s, logging to stdout only: %v", logPath, err)
		logPath = ""
	}
	defer log.SetOutput(os.Stderr)

	svc := &controlService{
		cfgPath:    cfgPath,
		token:      token,
		exePath:    exePath,
		logPath:    logPath,
		apiVersion: apiVersion,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", svc.withAuth(svc.handleStatus))
	mux.HandleFunc("/v1/start", svc.withAuth(svc.handleStart))
	mux.HandleFunc("/v1/stop", svc.withAuth(svc.handleStop))
	mux.HandleFunc("/v1/health", svc.withAuth(svc.handleHealth))
	mux.HandleFunc("/v1/validate", svc.withAuth(svc.handleValidate))
	mux.HandleFunc("/v1/logs", svc.withAuth(svc.handleLogs))
	mux.HandleFunc("/v1/scan", svc.withAuth(svc.handleScan))
	mux.HandleFunc("/v1/scan/start", svc.withAuth(svc.handleScanStart))
	mux.HandleFunc("/v1/scan/status", svc.withAuth(svc.handleScanStatus))
	mux.HandleFunc("/v1/apply", svc.withAuth(svc.handleApply))
	mux.HandleFunc("/v1/test", svc.withAuth(svc.handleTest))
	mux.HandleFunc("/v1/test/start", svc.withAuth(svc.handleTestStart))
	mux.HandleFunc("/v1/test/status", svc.withAuth(svc.handleTestStatus))
	mux.HandleFunc("/v1/config", svc.withAuth(svc.handleConfig))
	mux.HandleFunc("/v1/clients", svc.withAuth(svc.handleClients))
	mux.HandleFunc("/v1/interfaces", svc.withAuth(svc.handleInterfaces))

	srv := &http.Server{Addr: addr, Handler: mux}

	ctx, stop := signalContext()
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = svc.stopCore()
	}()

	if parentPID > 0 {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for range t.C {
				if !parentProcessAlive(parentPID, parentStartUnixMS) {
					logx.Warnf("control-service parent %d exited or changed; shutting down", parentPID)
					_ = svc.stopCore()
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_ = srv.Shutdown(shutdownCtx)
					cancel()
					return
				}
			}
		}()
	}

	logx.Infof("control-service listening on %s", addr)
	if token != "" {
		logx.Infof("control-service auth enabled")
	}
	if runtime.GOOS == "windows" && !rawinjector.IsRawAvailable() {
		diag := rawinjector.RawDiagnostic()
		if diag == "" {
			diag = "WinDivert handle open failed"
		}
		logx.Warnf("control-service: running without WinDivert / admin privileges; wrong_seq and raw fake_sni will not be available (%s)", diag)
	}

	err = srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// serviceLogPath picks a writable directory for the API log, most-reliable
// first. The config directory is the safest bet on Android: the installer
// seeded config.json there (/data/adb/snispf) so it's guaranteed writable.
// os.UserConfigDir() is unreliable for a root daemon — Magisk launches it with
// HOME unset and cwd "/", so it falls back to a relative "snispf" under the
// read-only rootfs ("mkdir snispf: read-only file system") and the daemon dies.
func serviceLogPath(cfgPath string) (string, error) {
	var bases []string
	if cfgPath != "" {
		if d := filepath.Dir(cfgPath); d != "" && d != "." {
			bases = append(bases, d)
		}
	}
	if b, err := os.UserConfigDir(); err == nil {
		bases = append(bases, filepath.Join(b, "snispf"))
	}
	bases = append(bases, os.TempDir())

	var lastErr error
	for _, base := range bases {
		dir := filepath.Join(base, "logs")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			lastErr = err
			continue
		}
		return filepath.Join(dir, "service.log"), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no candidate log directory")
	}
	return "", lastErr
}

func ensureLogSink(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	log.SetOutput(io.MultiWriter(os.Stdout, f))
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func (s *controlService) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" {
			provided := strings.TrimSpace(r.Header.Get("X-SNISPF-Token"))
			if provided == "" {
				provided = strings.TrimSpace(r.URL.Query().Get("token"))
			}
			if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func (s *controlService) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

func (s *controlService) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// Idempotent: starting an already-running core is a no-op success, not an
	// error (the WebUI tapping Connect when boot-autostart already ran).
	if s.status().Running {
		writeJSON(w, http.StatusOK, s.status())
		return
	}
	if err := s.startCore(); err != nil {
		// Return 200 with the reason: busybox wget (the WebUI bridge) drops the
		// body on 4xx, so the user would only see a bare "400 Bad Request".
		writeJSON(w, http.StatusOK, map[string]interface{}{"error": err.Error(), "status": s.status()})
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

func (s *controlService) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.status().Running { // already stopped = success
		writeJSON(w, http.StatusOK, s.status())
		return
	}
	if err := s.stopCore(); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"error": err.Error(), "status": s.status()})
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

func (s *controlService) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg, err := config.LoadOrDefault(s.cfgPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	config.Normalize(&cfg)
	active := config.EnabledEndpoints(cfg.Endpoints)
	if len(cfg.Listeners) > 0 {
		active = make([]config.Endpoint, 0, len(cfg.Listeners))
		for _, ls := range cfg.Listeners {
			resolvedIP := netutil.ResolveHost(ls.ConnectIP)
			active = append(active, config.Endpoint{
				Name:    ls.Name,
				IP:      resolvedIP,
				Port:    ls.ConnectPort,
				SNI:     ls.FakeSNI,
				Enabled: true,
			})
		}
	}
	timeout := time.Duration(cfg.ProbeTimeoutMS) * time.Millisecond
	// Bind the probe to the WAN device so it measures the real edge RTT instead
	// of a ~0ms local/tun path when a VPN is active (same fix as proxy/scanner).
	dev := netutil.ResolveWAN(cfg.Interface, cfg.ConnectIP)
	out := make([]healthEndpoint, 0, len(active))
	for _, ep := range active {
		healthy, latency, probeErr := probeTCPEndpoint(ep, timeout, dev)
		errText := ""
		if probeErr != nil {
			errText = probeErr.Error()
		}
		out = append(out, healthEndpoint{
			Name:      ep.Name,
			IP:        ep.IP,
			Port:      ep.Port,
			SNI:       ep.SNI,
			Healthy:   healthy,
			LatencyMS: latency.Milliseconds(),
			Error:     errText,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version": s.apiVersion,
		"checked_at":  time.Now().UTC(),
		"endpoints":   out,
		"wrong_seq":   s.collectWrongSeqHealthStats(5000),
	})
}

func (s *controlService) collectWrongSeqHealthStats(maxLines int) wrongSeqHealthStats {
	stats := wrongSeqHealthStats{}
	lines, err := tailLines(s.logPath, maxLines)
	if err != nil {
		return stats
	}
	stats.SourceLines = len(lines)

	for _, ln := range lines {
		if !strings.Contains(ln, "wrong_seq:") {
			continue
		}
		switch {
		case strings.Contains(ln, "confirmation succeeded"):
			stats.Confirmed++
		case strings.Contains(ln, "status=timeout") || strings.Contains(ln, "confirmation timeout"):
			stats.Timeout++
		case strings.Contains(ln, "status=not_registered"):
			stats.NotRegistered++
		case strings.Contains(ln, "status=failed"):
			stats.Failed++
		case strings.Contains(ln, "first payload write failed"):
			stats.FirstWriteFail++
		case strings.Contains(ln, "confirmation failed"):
			stats.Failed++
		}
	}

	return stats
}

// tailLines returns up to maxLines lines from the end of path. It reads
// backward in 64 KiB chunks until enough newlines are seen or the file is
// exhausted, so it doesn't load the whole file into memory like os.ReadFile.
// A maxLines <= 0 reads the whole file.
func tailLines(path string, maxLines int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if maxLines <= 0 {
		b, rerr := io.ReadAll(f)
		if rerr != nil {
			return nil, rerr
		}
		return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), nil
	}

	const chunk int64 = 64 * 1024
	buf := make([]byte, 0, chunk)
	tmp := make([]byte, chunk)
	pos := size
	newlines := 0
	for pos > 0 {
		readSize := chunk
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		if _, rerr := f.ReadAt(tmp[:readSize], pos); rerr != nil && rerr != io.EOF {
			return nil, rerr
		}
		buf = append(tmp[:readSize:readSize], buf...)
		newlines = 0
		for _, c := range buf {
			if c == '\n' {
				newlines++
			}
		}
		if newlines > maxLines {
			break
		}
	}
	lines := strings.Split(strings.ReplaceAll(string(buf), "\r\n", "\n"), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, nil
}

func (s *controlService) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg, err := config.LoadOrDefault(s.cfgPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	config.Normalize(&cfg)
	caps := platform.CheckCapabilities(rawinjector.IsRawAvailable())
	issues, warnings := config.RunDoctor(cfg, caps)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version": s.apiVersion,
		"issues":      issues,
		"warnings":    warnings,
	})
}

func (s *controlService) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	opts := scan.Options{
		PerRange: atoiDefault(q.Get("per_range"), 16),
		SNI:      strings.TrimSpace(q.Get("sni")),
		Threads:  atoiDefault(q.Get("threads"), 40),
		HitsOnly: q.Get("hits_only") == "1",
		HitsPath: s.hitsPath(),
		Save:     true,
	}
	if opts.SNI == "" {
		opts.SNI = scan.DefaultProbeSNI
	}
	// Pin probe dials to the WAN device so the scan works in full-tunnel VPN
	// mode and doesn't hang on the tun (which froze the UI).
	cfg, _ := config.LoadOrDefault(s.cfgPath)
	config.Normalize(&cfg)
	opts.Interface = netutil.ResolveWAN(cfg.Interface, cfg.ConnectIP)

	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	rep, err := scan.Run(ctx, opts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	applied := false
	if q.Get("apply") == "1" && rep.Best != nil {
		if err := s.applyEndpoint(rep.Best.IP, 443, opts.SNI); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "apply: " + err.Error()})
			return
		}
		applied = true
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version": s.apiVersion,
		"report":      rep,
		"applied":     applied,
	})
}

// handleScanStart kicks a scan in the background and returns immediately, so
// the WebUI polls /v1/scan/status instead of blocking on one long call.
func (s *controlService) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.scanMu.Lock()
	if s.scanRun {
		s.scanMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"running": true, "already": true})
		return
	}
	s.scanRun = true
	s.scanDone = false
	s.scanRep = nil
	s.scanErr = ""
	s.scanMu.Unlock()

	q := r.URL.Query()
	opts := scan.Options{
		PerRange: atoiDefault(q.Get("per_range"), 16),
		SNI:      strings.TrimSpace(q.Get("sni")),
		Threads:  atoiDefault(q.Get("threads"), 40),
		HitsOnly: q.Get("hits_only") == "1",
		HitsPath: s.hitsPath(),
		Save:     true,
	}
	if opts.SNI == "" {
		opts.SNI = scan.DefaultProbeSNI
	}
	cfg, _ := config.LoadOrDefault(s.cfgPath)
	config.Normalize(&cfg)
	opts.Interface = netutil.ResolveWAN(cfg.Interface, cfg.ConnectIP)

	// optional POST body: custom IP / domain lists to also probe
	var body struct {
		IPs     []string `json:"ips"`
		Domains []string `json:"domains"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	}
	opts.ExtraIPs = body.IPs
	opts.Domains = body.Domains

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
		defer cancel()
		rep, err := scan.Run(ctx, opts)
		s.scanMu.Lock()
		if err != nil {
			s.scanErr = err.Error()
		} else {
			r2 := rep
			s.scanRep = &r2
		}
		s.scanRun = false
		s.scanDone = true
		s.scanMu.Unlock()
	}()
	writeJSON(w, http.StatusOK, map[string]interface{}{"running": true, "started": true})
}

// handleScanStatus reports the background scan's progress/result. Cheap to poll.
func (s *controlService) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	resp := map[string]interface{}{
		"api_version": s.apiVersion,
		"running":     s.scanRun,
		"done":        s.scanDone,
	}
	if s.scanErr != "" {
		resp["error"] = s.scanErr
	}
	if s.scanRep != nil {
		resp["report"] = s.scanRep
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleTestStart kicks the auto-tune matrix in the background and returns at
// once; the WebUI polls /v1/test/status (the matrix can take ~2 min).
func (s *controlService) handleTestStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.testMu.Lock()
	if s.testRun {
		s.testMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"running": true, "already": true})
		return
	}
	s.testRun = true
	s.testDone = false
	s.testResults = nil
	s.testBest = nil
	s.testErr = ""
	s.testMu.Unlock()

	cfg, _ := config.LoadOrDefault(s.cfgPath)
	config.Normalize(&cfg)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 280*time.Second)
		defer cancel()
		results, err := matrix.Run(ctx, matrix.Options{ExePath: s.exePath, Base: cfg})
		s.testMu.Lock()
		if err != nil {
			s.testErr = err.Error()
		} else {
			s.testResults = results
			for i := range results {
				if results[i].Pass {
					s.testBest = &results[i]
					break
				}
			}
		}
		s.testRun = false
		s.testDone = true
		s.testMu.Unlock()
	}()
	writeJSON(w, http.StatusOK, map[string]interface{}{"running": true, "started": true})
}

// handleTestStatus reports auto-tune progress/result. Cheap to poll.
func (s *controlService) handleTestStatus(w http.ResponseWriter, r *http.Request) {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	resp := map[string]interface{}{
		"api_version": s.apiVersion,
		"running":     s.testRun,
		"done":        s.testDone,
	}
	if s.testErr != "" {
		resp["error"] = s.testErr
	}
	if s.testDone {
		resp["results"] = s.testResults
		resp["best"] = s.testBest
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleClients reports who is connected to the listener(s) — "is my VPN
// connected?" + "how many people?". Reads the kernel TCP table directly (the
// proxy core is a separate process, so we can't read its memory).
func (s *controlService) handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg, _ := config.LoadOrDefault(s.cfgPath)
	config.Normalize(&cfg)
	ports := listenPorts(cfg)
	active, byIP := tcpClientsFor(ports)

	type client struct {
		IP    string `json:"ip"`
		Conns int    `json:"conns"`
		Local bool   `json:"local"`
	}
	clients := make([]client, 0, len(byIP))
	for ip, n := range byIP {
		clients = append(clients, client{IP: ip, Conns: n, Local: ip == "127.0.0.1" || ip == "::1"})
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Conns > clients[j].Conns })

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version": s.apiVersion,
		"active":      active,
		"peers":       len(clients),
		"clients":     clients,
		"ports":       ports,
	})
}

// handleInterfaces lists physical WAN interfaces for the config picker, plus
// which one "auto" currently resolves to.
func (s *controlService) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg, _ := config.LoadOrDefault(s.cfgPath)
	config.Normalize(&cfg)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version": s.apiVersion,
		"interfaces":  netutil.WANInterfaces(),
		"auto":        netutil.PhysicalWANInterface(cfg.ConnectIP),
	})
}

func listenPorts(cfg config.Config) []int {
	seen := map[int]bool{}
	if cfg.ListenPort > 0 {
		seen[cfg.ListenPort] = true
	}
	for _, ls := range cfg.Listeners {
		if ls.ListenPort > 0 {
			seen[ls.ListenPort] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// tcpClientsFor counts ESTABLISHED connections whose local port is one of ports,
// grouping by remote IP. Reads /proc/net/tcp[6]; best-effort (empty off Linux).
func tcpClientsFor(ports []int) (active int, byIP map[string]int) {
	byIP = map[string]int{}
	if len(ports) == 0 {
		return 0, byIP
	}
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 {
				continue // header
			}
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "01" { // 01 = ESTABLISHED
				continue
			}
			if _, _, lport, ok := splitHexAddr(f[1]); !ok || !want[lport] {
				continue
			}
			rip, _, _, ok := splitHexAddr(f[2])
			if !ok || rip == "" {
				continue
			}
			byIP[rip]++
			active++
		}
	}
	return active, byIP
}

// splitHexAddr parses a /proc/net/tcp "ADDR:PORT" hex token into ip + port.
func splitHexAddr(tok string) (ip string, _ struct{}, port int, ok bool) {
	c := strings.LastIndex(tok, ":")
	if c < 0 {
		return "", struct{}{}, 0, false
	}
	p, err := strconv.ParseInt(tok[c+1:], 16, 32)
	if err != nil {
		return "", struct{}{}, 0, false
	}
	return hexToIP(tok[:c]), struct{}{}, int(p), true
}

// hexToIP converts a /proc/net hex address (little-endian v4, or v6) to a string.
func hexToIP(h string) string {
	switch len(h) {
	case 8: // IPv4, little-endian
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
			if err != nil {
				return ""
			}
			b[3-i] = byte(v)
		}
		return net.IPv4(b[0], b[1], b[2], b[3]).String()
	case 32: // IPv6 (per-32bit-word little-endian); ::ffff:a.b.c.d shown as v4
		raw := make([]byte, 16)
		for i := 0; i < 4; i++ {
			word := h[i*8 : i*8+8]
			for j := 0; j < 4; j++ {
				v, err := strconv.ParseUint(word[j*2:j*2+2], 16, 8)
				if err != nil {
					return ""
				}
				raw[i*4+(3-j)] = byte(v)
			}
		}
		ip := net.IP(raw)
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return ""
}

// handleConfig reads (GET) or replaces (POST) the full config. POST validates,
// writes, and restarts the core if it is running.
func (s *controlService) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := config.LoadOrDefault(s.cfgPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	case http.MethodPost:
		var cfg config.Config
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config json: " + err.Error()})
			return
		}
		config.Normalize(&cfg)
		if err := config.ValidateSNIGuardrails(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := config.Write(s.cfgPath, cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if s.status().Running {
			_ = s.stopCore()
			_ = s.startCore()
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"api_version": s.apiVersion,
			"saved":       true,
			"status":      s.status(),
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleTest auto-tunes: runs the uTLS×method matrix and returns PASS/FAIL per
// combo. apply=1 writes the best passing combo into the config and restarts.
func (s *controlService) handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg, err := config.LoadOrDefault(s.cfgPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	config.Normalize(&cfg)

	ctx, cancel := context.WithTimeout(r.Context(), 240*time.Second)
	defer cancel()
	results, err := matrix.Run(ctx, matrix.Options{ExePath: s.exePath, Base: cfg})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	applied := false
	var best *matrix.Result
	for i := range results {
		if results[i].Pass {
			best = &results[i]
			break
		}
	}
	if r.URL.Query().Get("apply") == "1" && best != nil {
		cfg.UTLS = best.Case.UTLS
		cfg.BypassMethod = best.Case.Method
		if err := config.Write(s.cfgPath, cfg); err == nil {
			if s.status().Running {
				_ = s.stopCore()
				_ = s.startCore()
			}
			applied = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version": s.apiVersion,
		"results":     results,
		"best":        best,
		"applied":     applied,
	})
}

// handleApply sets a user-chosen endpoint (e.g. a scan row picked in the WebUI)
// as CONNECT_IP/FAKE_SNI and restarts the core if running.
func (s *controlService) handleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	ip := strings.TrimSpace(q.Get("ip"))
	if net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or missing ip"})
		return
	}
	sni := strings.TrimSpace(q.Get("sni"))
	if sni == "" {
		sni = scan.DefaultProbeSNI
	}
	port := atoiDefault(q.Get("port"), 443)
	if err := s.applyEndpoint(ip, port, sni); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version":  s.apiVersion,
		"applied":      true,
		"connect_ip":   ip,
		"connect_port": port,
		"fake_sni":     sni,
		"status":       s.status(),
	})
}

// hitsPath stores the scan hit-list next to the config so survivors persist.
func (s *controlService) hitsPath() string {
	return filepath.Join(filepath.Dir(s.cfgPath), "cf_hits.json")
}

// applyEndpoint writes a chosen edge into the config and restarts the core if
// it is currently running so the new endpoint takes effect.
func (s *controlService) applyEndpoint(ip string, port int, sni string) error {
	cfg, err := config.LoadOrDefault(s.cfgPath)
	if err != nil {
		return err
	}
	if port <= 0 {
		port = 443
	}
	cfg.ConnectIP = ip
	cfg.ConnectPort = port
	cfg.FakeSNI = sni
	if err := config.Write(s.cfgPath, cfg); err != nil {
		return err
	}
	if s.status().Running {
		_ = s.stopCore()
		return s.startCore()
	}
	return nil
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return def
}

func (s *controlService) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			if n < 1 {
				n = 1
			}
			if n > 2000 {
				n = 2000
			}
			limit = n
		}
	}
	level := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("level")))
	if level == "ALL" {
		level = ""
	}

	// When filtering by level, read more raw lines than the limit so the
	// post-filter result still has a fighting chance to fill the cap.
	readLimit := limit
	if level != "" {
		readLimit = limit * 4
		if readLimit > 8000 {
			readLimit = 8000
		}
	}
	allLines, err := tailLines(s.logPath, readLimit)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"logs": ""})
		return
	}
	lines := make([]string, 0, len(allLines))
	for _, ln := range allLines {
		if level == "" {
			lines = append(lines, ln)
			continue
		}
		up := strings.ToUpper(ln)
		if strings.Contains(up, " "+level+" ") || strings.Contains(up, level+":") {
			lines = append(lines, ln)
		}
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version":    s.apiVersion,
		"logs":           strings.Join(lines, "\n"),
		"returned_lines": len(lines),
		"limit":          limit,
		"level":          level,
	})
}

func (s *controlService) startCore() error {
	s.mu.Lock()
	if s.starting {
		s.mu.Unlock()
		return fmt.Errorf("core start already in progress")
	}
	if s.child != nil && s.child.Process != nil {
		if s.child.ProcessState == nil || !s.child.ProcessState.Exited() {
			s.mu.Unlock()
			return fmt.Errorf("core already running")
		}
	}
	s.starting = true
	cfgPath := s.cfgPath
	exePath := s.exePath
	logPath := s.logPath
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.starting = false
		s.mu.Unlock()
	}()

	cfg, err := config.LoadOrDefault(cfgPath)
	if err != nil {
		return err
	}
	config.Normalize(&cfg)
	caps := platform.CheckCapabilities(rawinjector.IsRawAvailable())
	issues, _ := config.RunDoctor(cfg, caps)
	if len(issues) > 0 {
		return fmt.Errorf("config has %d issue(s); call /v1/validate", len(issues))
	}

	cmd := exec.Command(exePath, "--run-core", "--config", cfgPath)
	setHiddenProcessAttrs(cmd)

	lf, lferr := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if lferr == nil {
		cmd.Stdout = lf
		cmd.Stderr = lf
	}

	if err := cmd.Start(); err != nil {
		if lf != nil {
			_ = lf.Close()
		}
		s.mu.Lock()
		s.lastError = err.Error()
		s.mu.Unlock()
		return err
	}

	s.mu.Lock()
	s.child = cmd
	s.childLog = lf
	s.startedAt = time.Now().UTC()
	s.lastError = ""
	s.mu.Unlock()

	go func(c *exec.Cmd) {
		err := c.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.child == c {
			s.child = nil
			if s.childLog != nil {
				_ = s.childLog.Close()
				s.childLog = nil
			}
			if err != nil {
				s.lastError = err.Error()
			}
		}
	}(cmd)

	return nil
}

func (s *controlService) stopCore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.child == nil || s.child.Process == nil {
		s.child = nil
		return nil
	}
	err := s.child.Process.Kill()
	if s.childLog != nil {
		_ = s.childLog.Close()
		s.childLog = nil
	}
	s.child = nil
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "process already finished") {
		s.lastError = err.Error()
		return err
	}
	return nil
}

func (s *controlService) status() serviceStatus {
	rawAvail := rawinjector.IsRawAvailable()
	rawDiag := rawinjector.RawDiagnostic()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := serviceStatus{
		APIVersion:            s.apiVersion,
		Running:               false,
		ConfigPath:            s.cfgPath,
		LogPath:               s.logPath,
		LastError:             s.lastError,
		Platform:              runtime.GOOS,
		Architecture:          runtime.GOARCH,
		RawInjectionAvailable: rawAvail,
		RawDiagnostic:         rawDiag,
	}
	if s.child != nil && s.child.Process != nil {
		if s.child.ProcessState == nil || !s.child.ProcessState.Exited() {
			st.Running = true
			st.PID = s.child.Process.Pid
			st.StartedAt = s.startedAt
		}
	}
	return st
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// probeTCPEndpoint tests connectivity via a plain TCP dial (not TLS).
func probeTCPEndpoint(ep config.Endpoint, timeout time.Duration, dev string) (bool, time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	if ctrl := netutil.BindToDeviceControl(dev); ctrl != nil {
		d.Control = ctrl
	}
	start := time.Now()
	conn, err := d.Dial("tcp4", net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port)))
	if err != nil {
		return false, time.Since(start), err
	}
	_ = conn.Close()
	return true, time.Since(start), nil
}
