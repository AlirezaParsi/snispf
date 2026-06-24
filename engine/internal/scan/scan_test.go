package scan

import (
	"net"
	"testing"
)

func TestIsBogus(t *testing.T) {
	bogus := []string{"198.18.38.207", "10.1.2.3", "127.0.0.1", "100.64.0.1",
		"192.168.1.1", "garbage", ""}
	for _, ip := range bogus {
		if !isBogus(ip) {
			t.Errorf("%q should be bogus", ip)
		}
	}
	for _, ip := range []string{"104.19.229.21", "1.1.1.1", "172.64.1.1"} {
		if isBogus(ip) {
			t.Errorf("%q should NOT be bogus", ip)
		}
	}
}

func TestSampleCFIPs(t *testing.T) {
	ips := sampleCFIPs(10, 42)
	if len(ips) == 0 || len(ips) > 10*len(CloudflareV4) {
		t.Fatalf("unexpected sample count %d", len(ips))
	}
	// every sampled IP must be inside a CF range and never bogus
	var nets []*net.IPNet
	for _, c := range CloudflareV4 {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	for _, ip := range ips {
		if isBogus(ip) {
			t.Fatalf("sampled bogus ip %s", ip)
		}
		a := net.ParseIP(ip)
		in := false
		for _, n := range nets {
			if n.Contains(a) {
				in = true
				break
			}
		}
		if !in {
			t.Fatalf("sampled ip %s outside CF ranges", ip)
		}
	}
	// reproducible with the same seed
	if got := sampleCFIPs(5, 7); len(got) != len(sampleCFIPs(5, 7)) {
		t.Fatal("seed not reproducible")
	}
}

func TestHitListSurvivorsAndPrune(t *testing.T) {
	h := &hitList{Version: hitsVersion, IPs: map[string]*hitRec{}}
	h.update("1.2.3.4", statusOK, 50)   // clean -> survivor
	h.update("5.6.7.8", statusBlocked, 0)
	h.update("5.6.7.8", statusBlocked, 0)
	h.update("5.6.7.8", statusBlocked, 0) // 3 fails, never clean -> pruned
	if len(h.survivors()) != 1 || h.survivors()[0] != "1.2.3.4" {
		t.Fatalf("survivors = %v", h.survivors())
	}
	h.prune()
	if _, ok := h.IPs["5.6.7.8"]; ok {
		t.Fatal("never-clean ip should be pruned after 3 seen")
	}
	if _, ok := h.IPs["1.2.3.4"]; !ok {
		t.Fatal("survivor must be kept")
	}
}
