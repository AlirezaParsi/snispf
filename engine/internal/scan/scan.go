// Package scan finds reachable Cloudflare edge IPs without DNS and ranks them,
// for picking a CONNECT_IP that survives a national whitelist shutdown.
//
// Design carried over from the standalone sniscan.py, validated on the real
// Iran network:
//   - DNS is hijacked during shutdowns, so we scan Cloudflare's IP ranges
//     DIRECTLY (bundled below) instead of resolving names.
//   - Reachability is per-IP, not per-range: most sampled IPs are blackholed.
//   - Classify by the TLS-handshake outcome, which is what the DPI acts on:
//     handshake ok / TLS alert = clean path reached real CF; timeout = DPI
//     interference; dial failure / reset = blocked.
//   - speed.cloudflare.com is itself DPI-blocked in Iran — probe with a
//     DPI-allowed CF SNI (default www.cloudflare.com).
package scan

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"snispf/internal/netutil"
)

// CloudflareV4 are the official Cloudflare IPv4 ranges (cloudflare.com/ips-v4).
// Bundled so a scan needs no network/DNS to know where to probe.
var CloudflareV4 = []string{
	"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
	"198.41.128.0/17", "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
	"188.114.96.0/20", "197.234.240.0/22", "131.0.72.0/22",
}

// bogusCIDRs are DNS-hijack sinkholes / private / CGNAT / loopback ranges. An
// address here means the local intercept, never a real edge.
var bogusCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15",
	"192.0.0.0/24", "192.0.2.0/24",
}

var bogusNets []*net.IPNet

func init() {
	for _, c := range bogusCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			bogusNets = append(bogusNets, n)
		}
	}
}

// DefaultProbeSNI is a DPI-allowed, CF-served SNI. speed.cloudflare.com is
// DPI-blocked in Iran; do not use it here.
const DefaultProbeSNI = "www.cloudflare.com"

func isBogus(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return true
	}
	for _, n := range bogusNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// sampleCFIPs returns perRange random host IPs from each Cloudflare range.
func sampleCFIPs(perRange int, seed int64) []string {
	rng := rand.New(rand.NewSource(seed))
	var ips []string
	for _, cidr := range CloudflareV4 {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ones, bits := n.Mask.Size()
		hostBits := bits - ones
		if hostBits <= 1 {
			continue
		}
		size := uint64(1) << uint(hostBits)
		base := ipToU32(n.IP)
		seen := map[uint32]struct{}{}
		for i := 0; i < perRange; i++ {
			off := uint32(1 + rng.Int63n(int64(size-2)))
			if _, dup := seen[off]; dup {
				continue
			}
			seen[off] = struct{}{}
			ips = append(ips, u32ToIP(base+off))
		}
	}
	return ips
}

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func u32ToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// probe status values.
const (
	statusOK      = "ok"      // handshake completed: SNI passes DPI, edge served TLS
	statusAlert   = "alert"   // CF returned a TLS alert: reached real CF, clean path
	statusDPI     = "dpi"     // handshake timed out: DPI interference
	statusBlocked = "blocked" // TCP refused/reset or bogus address
)

// edgeProbe dials ip:443 directly and classifies the TLS handshake to sni. When
// dev is set the dial is pinned to that WAN device (SO_BINDTODEVICE) so probes
// leave the physical NIC instead of a VPN tun (full-tunnel correctness + avoids
// dials hanging on the tun, which is what froze the UI).
func edgeProbe(ip, sni, dev string, timeout time.Duration) (status string, rttMS float64) {
	if isBogus(ip) {
		return statusBlocked, 0
	}
	t0 := time.Now()
	d := net.Dialer{Timeout: timeout}
	if ctrl := netutil.BindToDeviceControl(dev); ctrl != nil {
		d.Control = ctrl
	}
	conn, err := d.Dial("tcp4", net.JoinHostPort(ip, "443"))
	if err != nil {
		return statusBlocked, 0
	}
	rtt := float64(time.Since(t0).Microseconds()) / 1000.0
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	err = tc.Handshake()
	if err == nil {
		return statusOK, rtt
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return statusDPI, rtt
	case strings.Contains(msg, "remote error: tls"):
		// the server spoke TLS back with an alert -> we reached real CF.
		return statusAlert, rtt
	default:
		// reset / EOF / broken pipe -> treat as blocked (often RST injection).
		return statusBlocked, rtt
	}
}

// Result is one ranked candidate.
type Result struct {
	IP     string  `json:"ip"`
	SNI    string  `json:"sni"`
	Host   string  `json:"host,omitempty"` // source domain, if this came from a domain
	RTTMS  float64 `json:"rtt_ms"`
	Status string  `json:"status"`
	Known  bool    `json:"known"`
	Clean  int     `json:"clean"`
	Seen   int     `json:"seen"`
}

// Report is the full scan outcome.
type Report struct {
	Results    []Result `json:"results"`
	Clean      int      `json:"clean"`
	DPIBlocked int      `json:"dpi_blocked"`
	TCPBlocked int      `json:"tcp_blocked"`
	Probed     int      `json:"probed"`
	Best       *Result  `json:"best,omitempty"`
}

// Options configures a scan.
type Options struct {
	PerRange int
	SNI      string
	Threads  int
	Timeout  time.Duration
	Seed     int64
	HitsPath string
	HitsOnly bool
	Save     bool
	// Interface pins probe dials to a WAN device (already resolved, not "auto").
	Interface string
	// ExtraIPs are user-supplied IPs to probe (default SNI). Domains are resolved
	// (DNS) and probed using the domain itself as the SNI — handy for finding
	// working fake-SNI / edge candidates beyond the bundled Cloudflare ranges.
	ExtraIPs []string
	Domains  []string
}

func (o *Options) applyDefaults() {
	if o.PerRange <= 0 {
		o.PerRange = 16
	}
	if strings.TrimSpace(o.SNI) == "" {
		o.SNI = DefaultProbeSNI
	}
	if o.Threads <= 0 {
		o.Threads = 40
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Seed == 0 {
		o.Seed = time.Now().UnixNano()
	}
}

type probeTarget struct {
	ip, sni, host string
	known         bool
}

// resolveDomainIPs resolves a domain to up to two non-bogus IPv4 addresses.
// (During a DNS hijack these come back as sinkholes and get filtered, so domain
// scanning is mainly a normal-times discovery tool.)
func resolveDomainIPs(domain string) []string {
	if domain == "" {
		return nil
	}
	addrs, err := net.LookupHost(domain)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !isBogus(a) {
			out = append(out, a)
			if len(out) >= 2 {
				break
			}
		}
	}
	return out
}

// Run probes Cloudflare IPs (hit-list survivors first, then sampled unless
// HitsOnly), plus any custom IPs/domains, classifies them, updates the hit-list,
// and returns ranked results.
func Run(ctx context.Context, opts Options) (Report, error) {
	opts.applyDefaults()

	hits := loadHits(opts.HitsPath)
	survivors := hits.survivors()

	known := map[string]bool{}
	for _, ip := range survivors {
		known[ip] = true
	}

	// Build the probe list. Each target carries its own SNI + source host so
	// custom IPs and domains are tested correctly alongside the CF ranges.
	var targets []probeTarget
	seen := map[string]bool{}
	add := func(ip, sni, host string, k bool) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return
		}
		key := ip + "|" + sni
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, probeTarget{ip: ip, sni: sni, host: host, known: k || known[ip]})
	}
	for _, ip := range survivors {
		add(ip, opts.SNI, "", true)
	}
	if !opts.HitsOnly {
		for _, ip := range sampleCFIPs(opts.PerRange, opts.Seed) {
			add(ip, opts.SNI, "", false)
		}
	}
	for _, ip := range opts.ExtraIPs {
		add(ip, opts.SNI, "", false)
	}
	for _, d := range opts.Domains {
		d = strings.TrimSpace(d)
		for _, ip := range resolveDomainIPs(d) {
			add(ip, d, d, false) // probe with the domain itself as SNI
		}
	}

	var (
		mu      sync.Mutex
		rows    []Result
		dpi     int
		blocked int
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, opts.Threads)

	for _, tg := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(tg probeTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			status, rtt := edgeProbe(tg.ip, tg.sni, opts.Interface, opts.Timeout)
			mu.Lock()
			defer mu.Unlock()
			rec := hits.update(tg.ip, status, rtt)
			switch status {
			case statusOK, statusAlert:
				if rtt == 0 {
					rtt = 9999
				}
				rows = append(rows, Result{
					IP: tg.ip, SNI: tg.sni, Host: tg.host, RTTMS: round1(rtt), Status: status,
					Known: tg.known, Clean: rec.Clean, Seen: rec.Seen,
				})
			case statusDPI:
				dpi++
			default:
				blocked++
			}
		}(tg)
	}
	wg.Wait()

	sort.Slice(rows, func(i, j int) bool { return rows[i].RTTMS < rows[j].RTTMS })

	hits.prune()
	if opts.Save && opts.HitsPath != "" {
		_ = saveHits(opts.HitsPath, hits)
	}

	rep := Report{
		Results: rows, Clean: len(rows), DPIBlocked: dpi, TCPBlocked: blocked,
		Probed: len(targets),
	}
	if len(rows) > 0 {
		best := rows[0]
		rep.Best = &best
	}
	return rep, nil
}

func dedupAppend(base, more []string) []string {
	seen := map[string]struct{}{}
	for _, s := range base {
		seen[s] = struct{}{}
	}
	for _, s := range more {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			base = append(base, s)
		}
	}
	return base
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

// ---- hit-list persistence ----

const (
	hitsVersion       = 1
	hitDropFailStreak = 8
	hitKeepDays       = 30
)

type hitRec struct {
	FirstSeen  int64   `json:"first_seen"`
	LastSeen   int64   `json:"last_seen"`
	LastClean  int64   `json:"last_clean"`
	Seen       int     `json:"seen"`
	Clean      int     `json:"clean"`
	Fail       int     `json:"fail"`
	FailStreak int     `json:"fail_streak"`
	LastRTT    float64 `json:"last_rtt"`
	LastStatus string  `json:"last_status"`
}

type hitList struct {
	Version int                `json:"version"`
	Updated int64              `json:"updated"`
	IPs     map[string]*hitRec `json:"ips"`
}

func loadHits(path string) *hitList {
	h := &hitList{Version: hitsVersion, IPs: map[string]*hitRec{}}
	if path == "" {
		return h
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return h
	}
	var parsed hitList
	if json.Unmarshal(b, &parsed) == nil && parsed.IPs != nil {
		return &parsed
	}
	return h
}

func (h *hitList) survivors() []string {
	var out []string
	for ip, r := range h.IPs {
		if r.Clean > 0 {
			out = append(out, ip)
		}
	}
	return out
}

func (h *hitList) update(ip, status string, rtt float64) *hitRec {
	now := time.Now().Unix()
	r := h.IPs[ip]
	if r == nil {
		r = &hitRec{FirstSeen: now}
		h.IPs[ip] = r
	}
	r.Seen++
	r.LastSeen = now
	r.LastStatus = status
	if status == statusOK || status == statusAlert {
		r.Clean++
		r.FailStreak = 0
		r.LastClean = now
		if rtt > 0 {
			r.LastRTT = round1(rtt)
		}
	} else {
		r.Fail++
		r.FailStreak++
	}
	return r
}

func (h *hitList) prune() {
	cutoff := time.Now().Unix() - int64(hitKeepDays)*86400
	for ip, r := range h.IPs {
		if r.FailStreak >= hitDropFailStreak ||
			(r.LastClean > 0 && r.LastClean < cutoff) ||
			(r.Clean == 0 && r.Seen >= 3) {
			delete(h.IPs, ip)
		}
	}
}

func saveHits(path string, h *hitList) error {
	h.Version = hitsVersion
	h.Updated = time.Now().Unix()
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
