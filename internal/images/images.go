package images

import (
	_ "embed"
	"io"
	"os"
	"path/filepath"
)

const (
	BuildVersion = "4"
	// AgentImage is the tooling source image: bash, node, python, git plus
	// the AEGIS /bin/sh workspace-jail wrapper. The runtime image is derived
	// from it by pruning it down to a strictly minimal, non-sensitive root
	// filesystem (see sandbox.EnsureRuntimeImage).
	AgentImage = "aegis-agent:v1"
	// RuntimeImage is the minimal hardened root filesystem the sandbox
	// actually runs from. It contains only what the agent's own processes
	// need to execute; /home, /var, /root, /srv, /opt and host-derived
	// configuration are absent, and /etc/passwd//etc/group are unreadable.
	RuntimeImage = "aegis-runtime:v1"
	ProxyImage   = "aegis-proxy:v1"
)

//go:embed docker/agent.Dockerfile
var agentDockerfile string

//go:embed docker/proxy.Dockerfile
var proxyDockerfile string

func AgentDockerfile() string { return agentDockerfile }

func ProxyDockerfile() string { return proxyDockerfile }

func WriteAgentContext(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(agentDockerfile), 0o600)
}

func WriteProxyContext(dir, proxyBinary string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(proxyDockerfile), 0o600); err != nil {
		return err
	}
	src, err := os.Open(proxyBinary)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(dir, "aegis-proxy"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}
