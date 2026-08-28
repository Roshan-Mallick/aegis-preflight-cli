package sandbox

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type inspectMount struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
	Type        string `json:"Type"`
}

type inspectConfig struct {
	Privileged bool     `json:"Privileged"`
	CapDrop    []string `json:"CapDrop"`
	User       string   `json:"User"`
}

type inspectResources struct {
	Memory    int64 `json:"Memory"`
	PidsLimit int64 `json:"PidsLimit"`
}

type inspectHostConfig struct {
	NetworkMode string   `json:"NetworkMode"`
	Privileged  bool     `json:"Privileged"`
	CapDrop     []string `json:"CapDrop"`

	PidsLimit int64
	Resources *inspectResources `json:"Resources"`
}

func (h *inspectHostConfig) UnmarshalJSON(b []byte) error {
	type alias struct {
		NetworkMode string            `json:"NetworkMode"`
		Privileged  bool              `json:"Privileged"`
		CapDrop     []string          `json:"CapDrop"`
		PidsLimit   int64             `json:"PidsLimit"`
		Resources   *inspectResources `json:"Resources"`
	}
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	h.NetworkMode = a.NetworkMode
	h.Privileged = a.Privileged
	h.CapDrop = a.CapDrop
	h.PidsLimit = a.PidsLimit
	h.Resources = a.Resources
	return nil
}

func (h *inspectHostConfig) EffectivePidsLimit() int64 {
	if h.PidsLimit > 0 {
		return h.PidsLimit
	}
	if h.Resources != nil && h.Resources.PidsLimit > 0 {
		return h.Resources.PidsLimit
	}
	return 0
}

type inspectItem struct {
	Name       string            `json:"Name"`
	Mounts     []inspectMount    `json:"Mounts"`
	Config     inspectConfig     `json:"Config"`
	HostConfig inspectHostConfig `json:"HostConfig"`
	State      struct {
		Running bool `json:"Running"`
	} `json:"State"`
}

func ParseInspect(raw []byte) ([]inspectItem, error) {
	var items []inspectItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("parse docker inspect output: %w", err)
	}
	if len(items) != 1 {
		return nil, fmt.Errorf("expected exactly one container in inspect output, got %d", len(items))
	}
	return items, nil
}

func VerifyIsolation(raw []byte, workspaceHostPath string) []string {
	items, err := ParseInspect(raw)
	if err != nil {
		return []string{err.Error()}
	}
	c := items[0]
	var v []string

	wsAbs, _ := filepath.Abs(workspaceHostPath)
	mounts := c.Mounts
	if len(mounts) == 0 {
		v = append(v, "no mounts found; /workspace mount missing")
	}
	wsFound := false
	for _, m := range mounts {
		if strings.HasPrefix(m.Destination, "/var/run/docker.sock") || m.Source == "/var/run/docker.sock" {
			v = append(v, "docker socket mounted into sandbox: "+m.Source)
		}
		if m.Destination == "/workspace" {
			wsFound = true
			srcAbs, _ := filepath.Abs(m.Source)
			if wsAbs != "" && srcAbs != wsAbs {
				v = append(v, "workspace mount source mismatch: "+m.Source)
			}
			if !m.RW {
				v = append(v, "/workspace is not read-write")
			}
		} else if m.Type == "bind" && !strings.HasPrefix(m.Destination, "/workspace") {
			v = append(v, "unexpected bind mount into sandbox: "+m.Destination+" <- "+m.Source)
		}
	}
	if !wsFound {
		v = append(v, "missing required /workspace mount")
	}

	network := c.HostConfig.NetworkMode
	if network != "none" {
		v = append(v, "network mode is "+network+", want none")
	}
	if c.HostConfig.Privileged || c.Config.Privileged {
		v = append(v, "container is privileged")
	}
	hasCapDropAll := false
	for _, cap := range c.HostConfig.CapDrop {
		if strings.EqualFold(cap, "ALL") {
			hasCapDropAll = true
		}
	}
	if !hasCapDropAll {
		v = append(v, "capabilities not dropped (CapDrop=ALL missing)")
	}
	user := c.Config.User
	if user == "" || user == "0" || user == "root" {
		v = append(v, "container runs as root")
	}
	if c.HostConfig.EffectivePidsLimit() <= 0 {
		v = append(v, "pids-limit not set")
	}
	return v
}
