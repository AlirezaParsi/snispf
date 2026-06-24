package config

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"snispf/internal/logx"
	"snispf/internal/netutil"
)

// ValidLoadBalanceModes lists the canonical values accepted for LoadBalance.
// Anything outside this set is normalised to "failover" and a warning is
// emitted so typos surface in the startup log instead of silently degrading
// to single-endpoint behaviour.
var ValidLoadBalanceModes = []string{"failover", "round_robin", "random"}

// Normalize applies defaults, resolves hosts, and fills in missing fields.
func Normalize(cfg *Config) {
	if strings.TrimSpace(cfg.LogLevel) == "" {
		cfg.LogLevel = "info"
	} else {
		cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	}

	rawLB := strings.ToLower(strings.TrimSpace(cfg.LoadBalance))
	switch rawLB {
	case "":
		cfg.LoadBalance = "failover"
	case "failover", "round_robin", "random":
		cfg.LoadBalance = rawLB
	default:
		logx.Warnf("unknown load_balance mode %q; falling back to %q (valid: %s)", cfg.LoadBalance, "failover", strings.Join(ValidLoadBalanceModes, ", "))
		cfg.LoadBalance = "failover"
	}
	if cfg.AutoFailover && cfg.FailoverRetries <= 0 {
		cfg.FailoverRetries = 2
	}
	if cfg.ProbeTimeoutMS <= 0 {
		cfg.ProbeTimeoutMS = 2500
	}
	if cfg.WrongSeqConfirmTimeoutMS <= 0 {
		cfg.WrongSeqConfirmTimeoutMS = 2000
	}

	for i := range cfg.Listeners {
		ls := &cfg.Listeners[i]
		if ls.ListenHost == "" {
			ls.ListenHost = cfg.ListenHost
		}
		if ls.ListenPort == 0 {
			ls.ListenPort = cfg.ListenPort
		}
		if ls.ConnectIP == "" {
			ls.ConnectIP = cfg.ConnectIP
		}
		if ls.ConnectPort == 0 {
			ls.ConnectPort = cfg.ConnectPort
		}
		if ls.FakeSNI == "" {
			ls.FakeSNI = cfg.FakeSNI
		}
		if ls.BypassMethod == "" {
			ls.BypassMethod = cfg.BypassMethod
		}
		ls.ConnectIP = netutil.ResolveHost(strings.TrimSpace(ls.ConnectIP))
	}

	if len(cfg.Listeners) > 0 {
		cfg.ListenHost = cfg.Listeners[0].ListenHost
		cfg.ListenPort = cfg.Listeners[0].ListenPort
		cfg.ConnectIP = cfg.Listeners[0].ConnectIP
		cfg.ConnectPort = cfg.Listeners[0].ConnectPort
		cfg.FakeSNI = cfg.Listeners[0].FakeSNI
	}

	if len(cfg.Endpoints) == 0 {
		cfg.Endpoints = []Endpoint{{
			Name:    "primary",
			IP:      cfg.ConnectIP,
			Port:    cfg.ConnectPort,
			SNI:     cfg.FakeSNI,
			Enabled: true,
		}}
	}

	for i := range cfg.Endpoints {
		ep := &cfg.Endpoints[i]
		if !ep.Enabled {
			continue
		}
		if ep.Port == 0 {
			ep.Port = cfg.ConnectPort
		}
		if ep.SNI == "" {
			ep.SNI = cfg.FakeSNI
		}
		ep.IP = netutil.ResolveHost(strings.TrimSpace(ep.IP))
	}

	if len(cfg.Endpoints) > 0 {
		// In listeners mode, top-level connect fields should reflect LISTENERS[0]
		// (used for summaries/doctor output), not endpoint[0].
		if len(cfg.Listeners) == 0 {
			cfg.ConnectIP = cfg.Endpoints[0].IP
			cfg.ConnectPort = cfg.Endpoints[0].Port
			cfg.FakeSNI = cfg.Endpoints[0].SNI
		}
	}
}

// EnabledEndpoints filters endpoints to those that are enabled and have valid fields.
func EnabledEndpoints(endpoints []Endpoint) []Endpoint {
	out := make([]Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		if !ep.Enabled {
			continue
		}
		if strings.TrimSpace(ep.IP) == "" || ep.Port == 0 || strings.TrimSpace(ep.SNI) == "" {
			continue
		}
		out = append(out, ep)
	}
	return out
}

// ProbeHealthyEndpoints runs health probes on all endpoints concurrently
// and returns only the healthy ones. Falls back to the full list if none pass.
func ProbeHealthyEndpoints(endpoints []Endpoint, timeout time.Duration) []Endpoint {
	if len(endpoints) <= 1 {
		return endpoints
	}

	type result struct {
		ep Endpoint
		ok bool
	}

	resCh := make(chan result, len(endpoints))
	var wg sync.WaitGroup
	for _, ep := range endpoints {
		ep := ep
		wg.Add(1)
		go func() {
			defer wg.Done()
			resCh <- result{ep: ep, ok: ProbeEndpoint(ep, timeout)}
		}()
	}
	wg.Wait()
	close(resCh)

	healthy := make([]Endpoint, 0, len(endpoints))
	for r := range resCh {
		if r.ok {
			healthy = append(healthy, r.ep)
		}
	}
	if len(healthy) == 0 {
		return endpoints
	}
	return healthy
}

// ProbeEndpoint tests connectivity to an endpoint via a TLS handshake.
func ProbeEndpoint(ep Endpoint, timeout time.Duration) bool {
	addr := net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port))
	dialer := &net.Dialer{Timeout: timeout}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         ep.SNI,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return false
	}
	_ = tlsConn.Close()
	return true
}
