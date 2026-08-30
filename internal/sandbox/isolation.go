package sandbox

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/eth0x1/aegis/internal/images"
)

type inspectMount struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
	Type        string `json:"Type"`
}

type inspectConfig struct {
	Image      string   `json:"Image"`
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

// allowedToolMount reports whether a bind mount is part of the documented
// minimal attachment set: the live project (/workspace) plus the controlled
// agent-tool chain mounted read-only under /usr/local/bin (agent binaries)
// and /agent (the single controlled agent, its config/data, and executable
// scratch space). Host system-library files pulled in by ldd for those
// binaries land on standard library paths and are regular (non-host-data)
// files, so they are accepted too. Anything else — a host directory, a
// credentials dir, a socket — is an unexpected host path and is flagged.
func allowedToolMount(dest, src string) bool {
	acceptedPrefixes := []string{
		"/workspace",
		"/usr/local/bin/",
		"/agent/",
		"/lib/",
		"/lib64/",
		"/usr/lib/",
		"/usr/lib64/",
		"/usr/bin/",
	}
	if dest == "/workspace" || dest == "/usr/local/bin" || dest == "/agent" {
		return true
	}
	for _, p := range acceptedPrefixes {
		if strings.HasPrefix(dest, p) {
			return true
		}
	}
	return false
}

func VerifyIsolation(raw []byte, workspaceHostPath string) []string {
	items, err := ParseInspect(raw)
	if err != nil {
		return []string{err.Error()}
	}
	c := items[0]
	var v []string

	// The container must run from the minimal runtime image — not the fat
	// tool image. This is the core filesystem-boundary assertion: the
	// runtime image is the pruned filesystem with no /home, /var, /root,
	// /srv, /opt and with an unreadable /etc/passwd, so the agent cannot
	// reach any of those paths by any means. (Config.Image is empty in
	// some minimal inspect fixtures, in which case the other checks still
	// apply.)
	if img := c.Config.Image; img != "" && !strings.HasPrefix(img, runtimeImagePrefix) {
		v = append(v, "sandbox image is not the minimal runtime (want "+images.RuntimeImage+"): "+img)
	}

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
		} else if m.Type == "bind" && !allowedToolMount(m.Destination, m.Source) {
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
