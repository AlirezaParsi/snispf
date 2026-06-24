// Package matrix auto-tunes the bypass: it spawns the core for each
// (uTLS fingerprint × bypass method) combination on a loopback port, runs a
// real HTTPS request through it, and reports which combos actually work — the
// snispf-core analogue of SNI-Spoofing-Go's -test matrix.
package matrix

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"time"

	"snispf/internal/config"
)

// Case is one combination to try.
type Case struct {
	UTLS   string `json:"utls"`
	Method string `json:"method"`
}

func (c Case) String() string { return fmt.Sprintf("utls=%s method=%s", c.UTLS, c.Method) }

// Result is the outcome of one case.
type Result struct {
	Case      Case   `json:"case"`
	Pass      bool   `json:"pass"`
	LatencyMS int64  `json:"latency_ms"`
	Err       string `json:"err,omitempty"`
}

// Options configures a matrix run.
type Options struct {
	ExePath string          // path to the snispf binary to spawn
	Base    config.Config   // base config (CONNECT_IP/FAKE_SNI taken from here)
	TestSNI string          // real SNI fetched through the tunnel (default www.cloudflare.com)
	Timeout time.Duration   // per-case timeout
	Cases   []Case          // combos to try (DefaultCases if empty)
}

// DefaultCases is a modest grid: a few fingerprints × the privileged + graceful
// methods. wrong_seq needs root; it simply FAILs without it.
func DefaultCases() []Case {
	utls := []string{"none", "firefox", "chrome"}
	methods := []string{"wrong_seq", "combined", "fragment"}
	out := make([]Case, 0, len(utls)*len(methods))
	for _, m := range methods {
		for _, u := range utls {
			out = append(out, Case{UTLS: u, Method: m})
		}
	}
	return out
}

// Run executes every case sequentially and returns results sorted best-first
// (passing cases by latency, then failures).
func Run(ctx context.Context, opts Options) ([]Result, error) {
	if opts.ExePath == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		opts.ExePath = exe
	}
	if opts.TestSNI == "" {
		opts.TestSNI = "www.cloudflare.com"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 12 * time.Second
	}
	if len(opts.Cases) == 0 {
		opts.Cases = DefaultCases()
	}

	results := make([]Result, 0, len(opts.Cases))
	for _, c := range opts.Cases {
		if ctx.Err() != nil {
			break
		}
		results = append(results, runOne(ctx, opts, c))
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Pass != results[j].Pass {
			return results[i].Pass // passing first
		}
		return results[i].LatencyMS < results[j].LatencyMS
	})
	return results, nil
}

func runOne(ctx context.Context, opts Options, c Case) Result {
	res := Result{Case: c}

	port, err := freeLoopbackPort()
	if err != nil {
		res.Err = "port: " + err.Error()
		return res
	}

	cfg := opts.Base
	cfg.ListenHost = "127.0.0.1"
	cfg.ListenPort = port
	cfg.UTLS = c.UTLS
	cfg.BypassMethod = c.Method
	// keep it single-endpoint and simple for the probe
	cfg.Listeners = nil
	cfg.Endpoints = nil

	tmp, err := os.CreateTemp("", "snispf-matrix-*.json")
	if err != nil {
		res.Err = "tmpcfg: " + err.Error()
		return res
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	_ = enc.Encode(cfg)
	_ = tmp.Close()

	caseCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	cmd := exec.Command(opts.ExePath, "--config", tmpPath, "--quiet")
	setProcGroup(cmd)
	if err := cmd.Start(); err != nil {
		res.Err = "spawn: " + err.Error()
		return res
	}
	defer terminate(cmd)

	listenAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	if !waitListening(caseCtx, listenAddr) {
		res.Err = "listener did not come up"
		return res
	}

	lat, err := probeThrough(caseCtx, listenAddr, opts.TestSNI, opts.Timeout)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Pass = true
	res.LatencyMS = lat.Milliseconds()
	return res
}

func freeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitListening(ctx context.Context, addr string) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// probeThrough makes an HTTPS request to testSNI BUT dials the local proxy, so
// the request travels through the bypass. Success = bytes returned.
func probeThrough(ctx context.Context, listenAddr, sni string, timeout time.Duration) (time.Duration, error) {
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", listenAddr)
		},
		TLSClientConfig:     &tls.Config{ServerName: sni, InsecureSkipVerify: true},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout}

	t0 := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+sni+"/cdn-cgi/trace", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	return time.Since(t0), nil
}
