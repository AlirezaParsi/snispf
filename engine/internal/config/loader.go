package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads and parses a JSON config file, using DefaultConfig as the base.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("failed to read config: %w", err)
	}
	cfg := DefaultConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("invalid config JSON: %w", err)
	}
	return cfg, nil
}

// Write serializes the config as indented JSON and writes it to a file.
func Write(path string, cfg Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// LoadOrDefault loads from the given path if it exists, otherwise returns DefaultConfig.
func LoadOrDefault(path string) (Config, error) {
	_, statErr := os.Stat(path)
	if statErr == nil {
		return Load(path)
	}
	if os.IsNotExist(statErr) {
		return DefaultConfig, nil
	}
	return Config{}, statErr
}
