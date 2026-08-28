package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	DefaultNetwork string            `json:"default_network,omitempty"`
	GitleaksPath   string            `json:"gitleaks_path,omitempty"`
	Scanners       ScannerConfig     `json:"scanners,omitempty"`
	Limits         LimitsConfig      `json:"limits,omitempty"`
	AllowedDomains []string          `json:"allowed_domains,omitempty"`
	Extra          map[string]string `json:"extra,omitempty"`
}

type ScannerConfig struct {
	Enabled []string `json:"enabled,omitempty"`
	Args    []string `json:"args,omitempty"`
}

type LimitsConfig struct {
	MemoryMB   int     `json:"memory_mb,omitempty"`
	CPUs       float64 `json:"cpus,omitempty"`
	MaxPIDs    int     `json:"max_pids,omitempty"`
	TimeoutSec int     `json:"timeout_sec,omitempty"`
}

var defaults = Config{
	DefaultNetwork: "strict",
	Limits: LimitsConfig{
		MemoryMB:   512,
		CPUs:       1.0,
		MaxPIDs:    64,
		TimeoutSec: 3600,
	},
}

func Load(projectRoot string) (*Config, error) {
	cfg := defaults

	projectConfig := filepath.Join(projectRoot, "aegis.json")
	if data, err := os.ReadFile(projectConfig); err == nil {
		var fileCfg Config
		if err := json.Unmarshal(data, &fileCfg); err == nil {
			merge(&cfg, &fileCfg)
		}
	}

	home, err := os.UserHomeDir()
	if err == nil {
		homeConfig := filepath.Join(home, ".config", "aegis", "config.json")
		if data, err := os.ReadFile(homeConfig); err == nil {
			var fileCfg Config
			if err := json.Unmarshal(data, &fileCfg); err == nil {
				merge(&cfg, &fileCfg)
			}
		}
	}

	return &cfg, nil
}

func merge(base, override *Config) {
	if override.DefaultNetwork != "" {
		base.DefaultNetwork = override.DefaultNetwork
	}
	if override.GitleaksPath != "" {
		base.GitleaksPath = override.GitleaksPath
	}
	if len(override.Scanners.Enabled) > 0 {
		base.Scanners.Enabled = override.Scanners.Enabled
	}
	if len(override.Scanners.Args) > 0 {
		base.Scanners.Args = override.Scanners.Args
	}
	if override.Limits.MemoryMB > 0 {
		base.Limits.MemoryMB = override.Limits.MemoryMB
	}
	if override.Limits.CPUs > 0 {
		base.Limits.CPUs = override.Limits.CPUs
	}
	if override.Limits.MaxPIDs > 0 {
		base.Limits.MaxPIDs = override.Limits.MaxPIDs
	}
	if override.Limits.TimeoutSec > 0 {
		base.Limits.TimeoutSec = override.Limits.TimeoutSec
	}
	if len(override.AllowedDomains) > 0 {
		base.AllowedDomains = override.AllowedDomains
	}
	if len(override.Extra) > 0 {
		if base.Extra == nil {
			base.Extra = map[string]string{}
		}
		for k, v := range override.Extra {
			base.Extra[k] = v
		}
	}
}

func Save(projectRoot string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(projectRoot, "aegis.json"), append(data, '\n'), 0o600)
}
