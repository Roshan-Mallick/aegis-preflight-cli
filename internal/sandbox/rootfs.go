package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/eth0x1/aegis/internal/images"
)

const (
	// bootstrapName is the short-lived container used to strip the tool
	// image down to the minimal runtime image.
	bootstrapName = "aegis-rootfs-bootstrap"

	// toolImageFingerprintEnv marks the runtime image with the agent image
	// ID it was derived from. If the tool image changes, the runtime image is
	// rebuilt (docker import --change ENV).
	toolImageFingerprintEnv = "AEGIS_RUNTIME_TOOL_IMAGE"

	// runtimeImagePrefix is the accepted image name prefix for the minimal
	// runtime root image (any tag of this name).
	runtimeImagePrefix = "aegis-runtime:"
)

// runtimePruneScript runs as root inside the bootstrap container. It removes
// every top-level path the agent has no business reaching and hardens /etc.
//
// The design principle: the sandbox root filesystem must not merely hide
// /home, /var, /root, /srv, /opt, /media, /mnt — they are deleted, so the
// agent cannot reach them by any absolute path, relative path (including
// trailing ".."), symlink, or filesystem API. /etc/passwd and /etc/group are
// root-owned mode 0600, so they exist for NSS edge cases but are UNREADABLE
// by the agent user: `cat /etc/passwd` fails with permission denied.
//
// Only what the agent's processes genuinely need to execute is preserved:
// the tool binaries under /bin, /sbin, /usr and their libraries, the TLS
// root bundle (/etc/ssl) needed for proxied egress, resolver/nsswitch
// config, the dynamic loader config, an empty /tmp and /run, and /workspace
// plus /agent/cache as mount targets. A system-wide /etc/gitconfig supplies
// a commit identity so git works without the (now unreadable) passwd file.
const runtimePruneScript = `set -u
rm -rf /var /home /root /srv /media /mnt /boot /opt /usr/src 2>/dev/null || true
rm -rf /usr/share/doc /usr/share/man /usr/share/info /usr/share/lintian \
  /usr/share/common-licenses /usr/share/locale /usr/share/bash-completion \
  /usr/share/vim 2>/dev/null || true
rm -f /etc/shadow /etc/gshadow /etc/subuid /etc/subgid 2>/dev/null || true
rm -rf /etc/skel /etc/pam.d /etc/apt /etc/update-motd.d /etc/logrotate.d \
  /etc/fstab /etc/mke2fs.conf /etc/issue* 2>/dev/null || true
printf 'root:x:0:0::/nonexistent:/usr/sbin/nologin\nnode:x:1000:1000::/workspace:/bin/bash\n' > /etc/passwd
chmod 600 /etc/passwd
printf 'root:x:0:\nnode:x:1000:\n' > /etc/group
chmod 600 /etc/group
printf '%s\n' 'passwd: files' 'group: files' 'shadow: files' 'hosts: files dns' 'networks: files' 'services: files' > /etc/nsswitch.conf
printf '[user]\n\tname = aegis-agent\n\temail = agent@aegis.local\n' > /etc/gitconfig
chmod 644 /etc/gitconfig
mkdir -p /workspace /agent/cache /tmp /run /etc/ld.so.conf.d
chmod 1777 /tmp
# /agent/cache is the agent's private scratch space (HOME and TMPDIR point
# here): owned by the agent uid and mode 0700 so only the agent can read or
# write it. /workspace stays owned by the agent too; its final (rw) bind
# mount carries the host project's own ownership.
chown -R 1000:1000 /workspace /agent/cache 2>/dev/null || true
chmod 700 /agent/cache
ldconfig >/dev/null 2>&1 || true
`

func imageID(ctx context.Context, name string) string {
	out, _ := docker(ctx, "images", "-q", name)
	return strings.TrimSpace(string(out))
}

// runtimeFingerprint returns the ENV fingerprint stored on the runtime
// image, or "" if the image does not exist yet.
func runtimeFingerprint(ctx context.Context) string {
	out, err := docker(ctx, "image", "inspect", images.RuntimeImage, "--format", "{{json .Config.Env}}")
	if err != nil {
		return ""
	}
	var env []string
	if err := json.Unmarshal(out, &env); err != nil {
		return ""
	}
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, toolImageFingerprintEnv+"="); ok {
			return v
		}
	}
	return ""
}

// EnsureRuntimeImage prepares the minimal hardened runtime image that the
// sandbox container runs from. It is idempotent: the image is only rebuilt
// when the tool image it derives from changes. Returns the image reference.
//
// The rebuild flow runs the prune script as root inside a throwaway
// bootstrap container (so file modes and ownership can be hardened), exports
// the pruned filesystem, and imports it as images.RuntimeImage. The result
// is a normal Docker image whose entire rootfs is exactly the curated
// minimum — no host user data, no /home, /var, /root, no readable
// /etc/passwd — enforced by the filesystem itself, not by shell policy.
func EnsureRuntimeImage(ctx context.Context) error {
	if err := EnsureAgentImage(ctx); err != nil {
		return err
	}
	toolID := imageID(ctx, images.AgentImage)
	if toolID == "" {
		return fmt.Errorf("agent tool image %s is not present", images.AgentImage)
	}
	if runtimeFingerprint(ctx) == toolID && runtimeBuildVersion(ctx) == images.BuildVersion {
		return nil
	}

	buildCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	_, _ = docker(buildCtx, "rm", "-f", bootstrapName)
	runArgs := []string{"run", "-d", "--name", bootstrapName, images.AgentImage}
	out, err := docker(buildCtx, runArgs...)
	if err != nil {
		return fmt.Errorf("start rootfs bootstrap container: %w: %s", err, trim(out))
	}
	defer func() { _, _ = docker(context.Background(), "rm", "-f", bootstrapName) }()

	out, err = docker(buildCtx, "exec", "-u", "0", bootstrapName, "sh", "-c", runtimePruneScript)
	if err != nil {
		return fmt.Errorf("prune runtime rootfs: %w: %s", err, trim(out))
	}

	exported, err := os.CreateTemp("", "aegis-rootfs-*.tar")
	if err != nil {
		return err
	}
	tarPath := exported.Name()
	defer func() { _ = exported.Close(); _ = os.Remove(tarPath) }()

	if err := dockerExportTo(buildCtx, bootstrapName, exported); err != nil {
		return err
	}
	if err := exported.Close(); err != nil {
		return err
	}

	out, err = docker(buildCtx,
		"import", "--change", strings.Join([]string{"ENV", toolImageFingerprintEnv + "=" + toolID}, " "),
		"--change", "LABEL com.aegis.managed=true", "--change", "LABEL com.aegis.resource=runtime-image",
		"--change", "LABEL com.aegis.build="+images.BuildVersion,
		tarPath, images.RuntimeImage)
	if err != nil {
		return fmt.Errorf("import runtime image: %w: %s", err, trim(out))
	}
	return nil
}

func runtimeBuildVersion(ctx context.Context) string {
	out, _ := docker(ctx, "image", "inspect", "--format", "{{index .Config.Labels \"com.aegis.build\"}}", images.RuntimeImage)
	return strings.TrimSpace(string(out))
}

// dockerExportTo writes `docker export <name>` to w.
func dockerExportTo(ctx context.Context, name string, w *os.File) error {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker binary not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, bin, "export", name)
	cmd.Stdout = w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker export %s: %w", name, err)
	}
	return nil
}
