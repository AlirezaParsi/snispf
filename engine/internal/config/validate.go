package config

import (
	"fmt"
	"net"
	"strings"

	"snispf/internal/logx"
	"snispf/internal/netutil"
	"snispf/internal/platform"
	"snispf/internal/tlsutil"
)

const (
	// MaxSNIBytes is the maximum allowed SNI hostname length in bytes.
	MaxSNIBytes = 219
	// MaxFakeHelloBytes is the maximum allowed fake ClientHello size.
	MaxFakeHelloBytes = 1460
)

// ValidateSNIGuardrails checks that SNI values in the config don't exceed
// size limits that would break raw injection.
func ValidateSNIGuardrails(cfg Config) error {
	check := func(scope, sni string) error {
		if len([]byte(sni)) > MaxSNIBytes {
			return fmt.Errorf("%s SNI must be <= %d bytes", scope, MaxSNIBytes)
		}
		n := len(tlsutil.BuildClientHello(sni))
		if n > MaxFakeHelloBytes {
			return fmt.Errorf("%s fake ClientHello size is %d bytes (> %d)", scope, n, MaxFakeHelloBytes)
		}
		return nil
	}
	if err := check("FAKE_SNI", cfg.FakeSNI); err != nil {
		return err
	}
	for i, ep := range cfg.Endpoints {
		if err := check(fmt.Sprintf("ENDPOINTS[%d].SNI", i), ep.SNI); err != nil {
			return err
		}
	}
	for i, ls := range cfg.Listeners {
		if err := check(fmt.Sprintf("LISTENERS[%d].FAKE_SNI", i), ls.FakeSNI); err != nil {
			return err
		}
	}
	return nil
}

// PrecedenceWarnings returns warnings about config fields being overridden
// by endpoint values.
func PrecedenceWarnings(cfg Config) []string {
	if len(cfg.Listeners) > 0 || len(cfg.Endpoints) == 0 {
		return nil
	}

	first := cfg.Endpoints[0]
	warnings := make([]string, 0, 3)

	cfgIP := strings.TrimSpace(netutil.ResolveHost(cfg.ConnectIP))
	epIP := strings.TrimSpace(netutil.ResolveHost(first.IP))
	if cfgIP != "" && epIP != "" && cfgIP != epIP {
		warnings = append(warnings,
			fmt.Sprintf("config precedence: ENDPOINTS[0].IP=%q overrides CONNECT_IP=%q", first.IP, cfg.ConnectIP),
		)
	}

	if cfg.ConnectPort > 0 && first.Port > 0 && cfg.ConnectPort != first.Port {
		warnings = append(warnings,
			fmt.Sprintf("config precedence: ENDPOINTS[0].PORT=%d overrides CONNECT_PORT=%d", first.Port, cfg.ConnectPort),
		)
	}

	cfgSNI := strings.TrimSpace(cfg.FakeSNI)
	epSNI := strings.TrimSpace(first.SNI)
	if cfgSNI != "" && epSNI != "" && !strings.EqualFold(cfgSNI, epSNI) {
		warnings = append(warnings,
			fmt.Sprintf("config precedence: ENDPOINTS[0].SNI=%q overrides FAKE_SNI=%q", first.SNI, cfg.FakeSNI),
		)
	}

	return warnings
}

// RunDoctor validates the config and returns any issues and warnings found.
func RunDoctor(cfg Config, caps platform.Capabilities) (issues []string, warnings []string) {
	if !netutil.IsValidPort(cfg.ListenPort) {
		issues = append(issues, "LISTEN_PORT must be between 1 and 65535")
	}
	if !netutil.IsValidPort(cfg.ConnectPort) {
		issues = append(issues, "CONNECT_PORT must be between 1 and 65535")
	}
	if cfg.ListenHost == "" {
		issues = append(issues, "LISTEN_HOST must not be empty")
	}
	if cfg.ConnectIP == "" {
		issues = append(issues, "CONNECT_IP must not be empty")
	}
	if _, ok := logx.ParseLevel(cfg.LogLevel); !ok {
		issues = append(issues, "LOG_LEVEL must be one of error, warn, info, debug")
	}
	if cfg.FakeSNI == "" {
		issues = append(issues, "FAKE_SNI must not be empty")
	}
	if len([]byte(cfg.FakeSNI)) > MaxSNIBytes {
		issues = append(issues, fmt.Sprintf("FAKE_SNI must be <= %d bytes", MaxSNIBytes))
	}
	if n := len(tlsutil.BuildClientHello(cfg.FakeSNI)); n > MaxFakeHelloBytes {
		issues = append(issues, fmt.Sprintf("FAKE_SNI generates fake ClientHello size %d bytes (> %d)", n, MaxFakeHelloBytes))
	}

	allowedMethods := map[string]bool{"fragment": true, "fake_sni": true, "combined": true, "wrong_seq": true}
	if !allowedMethods[strings.ToLower(cfg.BypassMethod)] {
		issues = append(issues, "BYPASS_METHOD must be one of fragment, fake_sni, combined, wrong_seq")
	}

	allowedFragments := map[string]bool{"sni_split": true, "half": true, "multi": true, "tls_record_frag": true}
	if !allowedFragments[strings.ToLower(cfg.FragmentStrategy)] {
		issues = append(issues, "FRAGMENT_STRATEGY must be one of sni_split, half, multi, tls_record_frag")
	}

	if cfg.FragmentDelay < 0 {
		issues = append(issues, "FRAGMENT_DELAY must be >= 0")
	}

	allowedLB := map[string]bool{}
	for _, m := range ValidLoadBalanceModes {
		allowedLB[m] = true
	}
	if cfg.LoadBalance != "" && !allowedLB[strings.ToLower(cfg.LoadBalance)] {
		issues = append(issues, "LOAD_BALANCE must be one of "+strings.Join(ValidLoadBalanceModes, ", "))
	}

	if cfg.FailoverRetries < 0 {
		issues = append(issues, "FAILOVER_RETRIES must be >= 0")
	}
	if cfg.ProbeTimeoutMS < 100 {
		warnings = append(warnings, "PROBE_TIMEOUT_MS is very low; endpoint probe may be unreliable")
	}
	if cfg.WrongSeqConfirmTimeoutMS < 100 {
		warnings = append(warnings, "WRONG_SEQ_CONFIRM_TIMEOUT_MS is very low; wrong_seq may fail under jitter")
	}

	enabledEndpoints := EnabledEndpoints(cfg.Endpoints)
	if len(cfg.Endpoints) > 0 && len(enabledEndpoints) == 0 {
		issues = append(issues, "ENDPOINTS present but none are valid+enabled")
	}
	for i, ep := range enabledEndpoints {
		if !netutil.IsValidPort(ep.Port) {
			issues = append(issues, fmt.Sprintf("ENDPOINTS[%d] port is invalid", i))
		}
		if strings.TrimSpace(ep.IP) == "" || strings.TrimSpace(ep.SNI) == "" {
			issues = append(issues, fmt.Sprintf("ENDPOINTS[%d] must include IP and SNI", i))
		}
		if len([]byte(ep.SNI)) > MaxSNIBytes {
			issues = append(issues, fmt.Sprintf("ENDPOINTS[%d].SNI must be <= %d bytes", i, MaxSNIBytes))
		}
		if n := len(tlsutil.BuildClientHello(ep.SNI)); n > MaxFakeHelloBytes {
			issues = append(issues, fmt.Sprintf("ENDPOINTS[%d].SNI generates fake ClientHello size %d bytes (> %d)", i, n, MaxFakeHelloBytes))
		}
	}

	for i, ls := range cfg.Listeners {
		if !netutil.IsValidPort(ls.ListenPort) {
			issues = append(issues, fmt.Sprintf("LISTENERS[%d].LISTEN_PORT is invalid", i))
		}
		if !netutil.IsValidPort(ls.ConnectPort) {
			issues = append(issues, fmt.Sprintf("LISTENERS[%d].CONNECT_PORT is invalid", i))
		}
		if strings.TrimSpace(ls.ListenHost) == "" || strings.TrimSpace(ls.ConnectIP) == "" || strings.TrimSpace(ls.FakeSNI) == "" {
			issues = append(issues, fmt.Sprintf("LISTENERS[%d] must include LISTEN_HOST, CONNECT_IP, and FAKE_SNI", i))
		}
		if len([]byte(ls.FakeSNI)) > MaxSNIBytes {
			issues = append(issues, fmt.Sprintf("LISTENERS[%d].FAKE_SNI must be <= %d bytes", i, MaxSNIBytes))
		}
		if n := len(tlsutil.BuildClientHello(ls.FakeSNI)); n > MaxFakeHelloBytes {
			issues = append(issues, fmt.Sprintf("LISTENERS[%d].FAKE_SNI generates fake ClientHello size %d bytes (> %d)", i, n, MaxFakeHelloBytes))
		}
	}

	allowedFakeMethods := map[string]bool{"prefix_fake": true, "ttl_trick": true, "disorder": true, "fragment_fallback": true, "raw_inject": true}
	if !allowedFakeMethods[strings.ToLower(cfg.FakeSNIMethod)] {
		warnings = append(warnings, "FAKE_SNI_METHOD is uncommon; expected prefix_fake, ttl_trick, or disorder")
	}

	if (strings.ToLower(cfg.BypassMethod) == "fake_sni" || strings.ToLower(cfg.BypassMethod) == "combined" || strings.ToLower(cfg.BypassMethod) == "wrong_seq") && !caps.RawInjection {
		warnings = append(warnings, "raw injection unavailable; fake_sni/combined use fallback, wrong_seq cannot operate")
	}

	if strings.ToLower(cfg.BypassMethod) == "wrong_seq" && len(enabledEndpoints) != 1 {
		issues = append(issues, "wrong_seq requires exactly one enabled endpoint")
	}

	if cfg.UseTTLTrick && !caps.IPTTLTrick {
		warnings = append(warnings, "USE_TTL_TRICK enabled but platform capabilities indicate TTL trick may not work")
	}

	if ifName := strings.TrimSpace(cfg.Interface); ifName != "" && !strings.EqualFold(ifName, "auto") {
		// "auto" is resolved at runtime to the physical WAN; not a literal name.
		if _, err := net.InterfaceByName(ifName); err != nil {
			warnings = append(warnings, fmt.Sprintf("INTERFACE=%q not found on this system: %v", ifName, err))
		}
	}

	return issues, warnings
}
