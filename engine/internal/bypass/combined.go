package bypass

import (
	"context"
	"net"
	"time"

	"snispf/internal/logx"
	"snispf/internal/rawinjector"
	"snispf/internal/tlsutil"
)

type Combined struct {
	strategy string
	delay    time.Duration
	useTTL   bool
	confirm  time.Duration
	injector rawinjector.Interface
}

func NewCombined(strategy string, delaySec float64, useTTL bool, confirmTimeout time.Duration, injector rawinjector.Interface) *Combined {
	if confirmTimeout <= 0 {
		confirmTimeout = 2 * time.Second
	}
	return &Combined{strategy: strategy, delay: time.Duration(delaySec * float64(time.Second)), useTTL: useTTL, confirm: confirmTimeout, injector: injector}
}

func (c *Combined) Name() string { return "combined" }

func (c *Combined) Apply(_ context.Context, _ net.Conn, serverConn *net.TCPConn, fakeSNI string, firstData []byte) bool {
	if c.injector != nil {
		port := serverConn.LocalAddr().(*net.TCPAddr).Port
		status := c.injector.WaitForConfirmationDetailed(port, c.confirm)
		switch status {
		case rawinjector.ConfirmationStatusConfirmed:
			// happy path; nothing to log
		case rawinjector.ConfirmationStatusFailed:
			logx.Warnf("combined: raw confirmation reported failure port=%d, continuing with fragmentation", port)
		case rawinjector.ConfirmationStatusTimeout:
			logx.Warnf("combined: raw confirmation timed out port=%d timeout=%s, continuing with fragmentation", port, c.confirm)
		case rawinjector.ConfirmationStatusNotRegistered:
			logx.Warnf("combined: raw confirmation port not registered port=%d, continuing with fragmentation", port)
		}
	} else if c.useTTL {
		fakeHello := tlsutil.BuildClientHello(fakeSNI)
		originalTTL, ttlErr := getConnTTL(serverConn)
		if ttlErr == nil {
			if err := setConnTTL(serverConn, 3); err == nil {
				_, _ = serverConn.Write(fakeHello)
				time.Sleep(50 * time.Millisecond)
				_ = setConnTTL(serverConn, originalTTL)
			} else {
				_, _ = serverConn.Write(fakeHello)
			}
		} else {
			_, _ = serverConn.Write(fakeHello)
		}
		time.Sleep(1 * time.Millisecond)
	}

	_ = serverConn.SetNoDelay(true)
	defer serverConn.SetNoDelay(false)
	frags := tlsutil.FragmentClientHello(firstData, c.strategy)
	for i, frag := range frags {
		if _, err := serverConn.Write(frag); err != nil {
			return false
		}
		if i < len(frags)-1 && c.delay > 0 {
			time.Sleep(tlsutil.JitterDelay(c.delay))
		}
	}
	return true
}
