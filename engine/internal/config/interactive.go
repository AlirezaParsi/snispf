package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// RunInteractiveUI provides an interactive command-line config editor.
func RunInteractiveUI(cfg Config) (Config, error) {
	r := bufio.NewReader(os.Stdin)
	fmt.Println("Interactive config editor")
	fmt.Println("Press Enter to keep current values.")

	cfg.ListenHost = promptString(r, "LISTEN_HOST", cfg.ListenHost)
	cfg.ListenPort = promptInt(r, "LISTEN_PORT", cfg.ListenPort)
	cfg.LogLevel = strings.ToLower(promptString(r, "LOG_LEVEL [error|warn|info|debug]", cfg.LogLevel))
	cfg.ConnectIP = promptString(r, "CONNECT_IP", cfg.ConnectIP)
	cfg.ConnectPort = promptInt(r, "CONNECT_PORT", cfg.ConnectPort)
	cfg.FakeSNI = promptString(r, "FAKE_SNI", cfg.FakeSNI)
	cfg.BypassMethod = strings.ToLower(promptString(r, "BYPASS_METHOD [fragment|fake_sni|combined|wrong_seq]", cfg.BypassMethod))
	cfg.FragmentStrategy = strings.ToLower(promptString(r, "FRAGMENT_STRATEGY [sni_split|half|multi|tls_record_frag]", cfg.FragmentStrategy))
	cfg.FragmentDelay = promptFloat(r, "FRAGMENT_DELAY", cfg.FragmentDelay)
	cfg.UseTTLTrick = promptBool(r, "USE_TTL_TRICK", cfg.UseTTLTrick)
	cfg.FakeSNIMethod = strings.ToLower(promptString(r, "FAKE_SNI_METHOD [prefix_fake|ttl_trick|disorder]", cfg.FakeSNIMethod))
	cfg.WrongSeqConfirmTimeoutMS = promptInt(r, "WRONG_SEQ_CONFIRM_TIMEOUT_MS", cfg.WrongSeqConfirmTimeoutMS)
	cfg.Interface = promptString(r, "INTERFACE (network interface name, empty=auto)", cfg.Interface)

	return cfg, nil
}

func promptString(r *bufio.Reader, label, current string) string {
	fmt.Printf("%s [%s]: ", label, current)
	text, _ := r.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return current
	}
	return text
}

func promptInt(r *bufio.Reader, label string, current int) int {
	for {
		fmt.Printf("%s [%d]: ", label, current)
		text, _ := r.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			return current
		}
		v, err := strconv.Atoi(text)
		if err == nil {
			return v
		}
		fmt.Println("Invalid integer, try again.")
	}
}

func promptFloat(r *bufio.Reader, label string, current float64) float64 {
	for {
		fmt.Printf("%s [%.3f]: ", label, current)
		text, _ := r.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			return current
		}
		v, err := strconv.ParseFloat(text, 64)
		if err == nil {
			return v
		}
		fmt.Println("Invalid number, try again.")
	}
}

func promptBool(r *bufio.Reader, label string, current bool) bool {
	for {
		fmt.Printf("%s [%v]: ", label, current)
		text, _ := r.ReadString('\n')
		text = strings.TrimSpace(strings.ToLower(text))
		if text == "" {
			return current
		}
		switch text {
		case "true", "t", "yes", "y", "1":
			return true
		case "false", "f", "no", "n", "0":
			return false
		default:
			fmt.Println("Invalid boolean, use true/false.")
		}
	}
}
