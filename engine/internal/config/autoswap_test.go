package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAutoSwapEnabledDefaultsTrue(t *testing.T) {
	// Unset (nil) must default to enabled.
	if !(Config{}).AutoSwapEnabled() {
		t.Fatal("AutoSwap unset should default to enabled")
	}
	f := false
	if (Config{AutoSwap: &f}).AutoSwapEnabled() {
		t.Fatal("AutoSwap=false should be disabled")
	}
	tr := true
	if !(Config{AutoSwap: &tr}).AutoSwapEnabled() {
		t.Fatal("AutoSwap=true should be enabled")
	}
}

// An explicit AUTO_SWAP=false must survive a load → write → load round-trip. A
// plain bool with omitempty would drop the false and silently re-enable it; the
// *bool guards against that.
func TestAutoSwapFalsePersistsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"AUTO_SWAP": false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoSwapEnabled() {
		t.Fatal("loaded AUTO_SWAP=false but reports enabled")
	}
	if err := Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.AutoSwapEnabled() {
		t.Fatal("AUTO_SWAP=false did not survive write→load round-trip")
	}
}

// Write must be atomic: a successful Write leaves no temp file and a valid file.
func TestWriteAtomicNoTempLeft(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := Write(path, DefaultConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind after Write")
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("written config not loadable: %v", err)
	}
}
