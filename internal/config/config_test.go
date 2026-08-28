package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultNetwork != "strict" {
		t.Errorf("default network = %s, want strict", cfg.DefaultNetwork)
	}
	if cfg.Limits.MemoryMB != 512 {
		t.Errorf("memory = %d, want 512", cfg.Limits.MemoryMB)
	}
	if cfg.Limits.CPUs != 1.0 {
		t.Errorf("cpus = %f, want 1.0", cfg.Limits.CPUs)
	}
}

func TestLoadOverrides(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "aegis.json"), []byte(`{
		"default_network": "dev",
		"gitleaks_path": "/usr/local/bin/gitleaks",
		"limits": {"memory_mb": 1024, "cpus": 2.0}
	}`), 0o600)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultNetwork != "dev" {
		t.Errorf("network = %s, want dev", cfg.DefaultNetwork)
	}
	if cfg.GitleaksPath != "/usr/local/bin/gitleaks" {
		t.Errorf("gitleaks = %s", cfg.GitleaksPath)
	}
	if cfg.Limits.MemoryMB != 1024 {
		t.Errorf("memory = %d, want 1024", cfg.Limits.MemoryMB)
	}
	if cfg.Limits.CPUs != 2.0 {
		t.Errorf("cpus = %f, want 2.0", cfg.Limits.CPUs)
	}
	if cfg.Limits.MaxPIDs != 64 {
		t.Errorf("max_pids = %d, want 64 (default)", cfg.Limits.MaxPIDs)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		DefaultNetwork: "dev",
		GitleaksPath:   "/custom/gitleaks",
		Limits: LimitsConfig{
			MemoryMB: 2048,
			CPUs:     4.0,
			MaxPIDs:  128,
		},
	}
	if err := Save(dir, cfg); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "aegis.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty config file")
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DefaultNetwork != "dev" {
		t.Errorf("network = %s", loaded.DefaultNetwork)
	}
	if loaded.Limits.MemoryMB != 2048 {
		t.Errorf("memory = %d", loaded.Limits.MemoryMB)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "aegis.json"), []byte(`{invalid`), 0o600)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultNetwork != "strict" {
		t.Error("should fall back to defaults on invalid JSON")
	}
}

func TestLoadNoFile(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultNetwork != "strict" {
		t.Errorf("network = %s, want strict", cfg.DefaultNetwork)
	}
}
