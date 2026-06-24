package tlsutil

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// fingerprint is the process-wide uTLS preset for the fake ClientHello, set once
// at core startup from config (UTLS). Empty / "none" keeps the legacy builder.
var (
	fpMu        sync.RWMutex
	fingerprint string
)

// SetFingerprint selects the browser fingerprint used by BuildClientHello.
func SetFingerprint(name string) {
	fpMu.Lock()
	fingerprint = strings.ToLower(strings.TrimSpace(name))
	fpMu.Unlock()
}

// Fingerprint returns the active fingerprint name ("" when legacy).
func Fingerprint() string {
	fpMu.RLock()
	defer fpMu.RUnlock()
	return fingerprint
}

// clientHelloID maps a preset name to a uTLS ClientHelloID. ok=false for legacy.
func clientHelloID(name string) (utls.ClientHelloID, bool) {
	switch name {
	case "firefox":
		return utls.HelloFirefox_Auto, true
	case "chrome":
		return utls.HelloChrome_Auto, true
	case "safari":
		return utls.HelloSafari_Auto, true
	case "ios":
		return utls.HelloIOS_Auto, true
	case "edge":
		return utls.HelloEdge_Auto, true
	case "randomized", "random":
		return utls.HelloRandomized, true
	default:
		return utls.ClientHelloID{}, false
	}
}

// UTLSPresets are the selectable fingerprint names (for the WebUI / validation).
var UTLSPresets = []string{"none", "firefox", "chrome", "safari", "ios", "edge", "randomized"}

// buildUTLSClientHelloRecord produces a full TLS record (handshake type 22)
// carrying a real-browser ClientHello for serverName.
func buildUTLSClientHelloRecord(serverName string, id utls.ClientHelloID) ([]byte, error) {
	if serverName == "" {
		return nil, fmt.Errorf("tlsutil: empty server name")
	}
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = io.Copy(io.Discard, server)
		_ = server.Close()
	}()

	uconn := utls.UClient(client, &utls.Config{ServerName: serverName}, id)
	if err := uconn.BuildHandshakeStateWithoutSession(); err != nil {
		return nil, fmt.Errorf("tlsutil: build uTLS ClientHello: %w", err)
	}
	hs := uconn.HandshakeState.Hello.Raw
	if len(hs) == 0 {
		return nil, fmt.Errorf("tlsutil: empty uTLS ClientHello")
	}
	ver := uint16(utls.VersionTLS12) // record-layer version (variable avoids const overflow)
	out := make([]byte, 5+len(hs))
	out[0] = 22 // handshake
	out[1] = byte(ver >> 8)
	out[2] = byte(ver)
	out[3] = byte(len(hs) >> 8)
	out[4] = byte(len(hs))
	copy(out[5:], hs)
	return out, nil
}
