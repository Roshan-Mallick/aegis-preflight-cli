#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR=${AEGIS_STATE_DIR:-"${HOME}/.local/state/aegis"}
BIN_DIR="${STATE_DIR}/bin"
BOOTSTRAP_NETWORK=${AEGIS_BOOTSTRAP_NETWORK:-aegis-bootstrap}
SOURCE_CLI="${ROOT_DIR}/aegis"

fail() {
  printf 'AEGIS build failed: %s\n' "$1" >&2
  printf 'Action: %s\n' "${2:-resolve the issue and rerun ./build.sh}" >&2
  exit 1
}
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is missing" "install '$1' for your Linux distribution, then rerun ./build.sh"; }

INSTALL_DIR=""
old_ifs=$IFS
IFS=:
for path_dir in $PATH; do
  IFS=$old_ifs
  [[ -d "$path_dir" && -w "$path_dir" ]] && { INSTALL_DIR="$path_dir"; break; }
  IFS=:
done
IFS=$old_ifs
if [[ -z "$INSTALL_DIR" ]]; then
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi
CLI="${INSTALL_DIR}/aegis"
LIB_DIR="$(cd "${INSTALL_DIR}/.." && pwd)/lib/aegis"

[[ "$(uname -s)" == Linux ]] || fail "unsupported platform $(uname -s)" "run AEGIS on Linux amd64"
[[ "$(uname -m)" == x86_64 || "$(uname -m)" == amd64 ]] || fail "unsupported architecture $(uname -m)" "run AEGIS on Linux x86-64"
need_cmd go
need_cmd docker
need_cmd git

GO_VERSION=$(go version | awk '{print $3}' | sed 's/^go//')
GO_MAJOR=$(printf '%s\n' "$GO_VERSION" | cut -d. -f1)
GO_MINOR=$(printf '%s\n' "$GO_VERSION" | cut -d. -f2)
[[ "$GO_MAJOR" -gt 1 || ( "$GO_MAJOR" -eq 1 && "$GO_MINOR" -ge 27 ) ]] || fail "Go ${GO_VERSION} is too old" "install Go 1.27 or newer"
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 || fail "Docker daemon is unavailable or permission was denied" "start Docker Engine and grant this user access to it"

state_preexisting=0
[[ -e "$STATE_DIR" ]] && state_preexisting=1
mkdir -p "$BIN_DIR" "$STATE_DIR/cache" "$STATE_DIR/tmp" "$STATE_DIR/sessions"
mkdir -p "$LIB_DIR"
chmod 700 "$STATE_DIR" "$BIN_DIR" "$STATE_DIR/cache" "$STATE_DIR/tmp" "$STATE_DIR/sessions"
if [[ "$state_preexisting" -eq 0 ]]; then
  touch "${STATE_DIR}/.aegis-managed-state" "${BIN_DIR}/.aegis-managed" "${STATE_DIR}/cache/.aegis-managed" "${STATE_DIR}/tmp/.aegis-managed" "${STATE_DIR}/sessions/.aegis-managed"
  chmod 600 "${STATE_DIR}/.aegis-managed-state" "${BIN_DIR}/.aegis-managed" "${STATE_DIR}/cache/.aegis-managed" "${STATE_DIR}/tmp/.aegis-managed" "${STATE_DIR}/sessions/.aegis-managed"
fi

CONFIG_FILE="${ROOT_DIR}/aegis.json"
if [[ ! -e "$CONFIG_FILE" ]]; then
  printf '{\n  "default_network": "strict"\n}\n' > "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
  touch "${STATE_DIR}/.aegis-managed-config"
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  GOBIN="$BIN_DIR" go install github.com/gitleaks/gitleaks/v8@v8.30.2 || fail "could not install gitleaks" "ensure Go can download modules, or install gitleaks and rerun ./build.sh"
fi
GITLEAKS=$(command -v gitleaks 2>/dev/null || true)
[[ -n "$GITLEAKS" ]] || GITLEAKS="${BIN_DIR}/gitleaks"
[[ -x "$GITLEAKS" ]] || fail "gitleaks was not produced" "install gitleaks and rerun ./build.sh"

printf 'Building AEGIS CLI...\n'
go build -trimpath -ldflags='-s -w' -o "$SOURCE_CLI" ./cmd/aegis
printf 'Building AEGIS proxy...\n'
go build -trimpath -ldflags='-s -w' -o "${LIB_DIR}/aegis-proxy" ./cmd/aegis-proxy
install -m 755 "$SOURCE_CLI" "$CLI"
[[ -x "$CLI" && -x "${LIB_DIR}/aegis-proxy" ]] || fail "compiled binaries are missing" "inspect the Go build output"
printf '%s\n' "$CLI" > "${STATE_DIR}/.aegis-cli-path"
printf '%s\n' "$LIB_DIR" > "${STATE_DIR}/.aegis-proxy-dir"

export AEGIS_REPO_ROOT="$ROOT_DIR"
export PATH="${BIN_DIR}:${PATH}"
export AEGIS_GITLEAKS_PATH="$GITLEAKS"
"$CLI" init

if ! docker network inspect "$BOOTSTRAP_NETWORK" >/dev/null 2>&1; then
  docker network create --internal --driver bridge \
    --label com.aegis.managed=true \
    --label com.aegis.resource=bootstrap-network \
    "$BOOTSTRAP_NETWORK" >/dev/null
fi

"$CLI" doctor
"$CLI" --version >/dev/null
command -v aegis >/dev/null 2>&1 || fail "aegis is not discoverable on PATH" "add ${INSTALL_DIR} to PATH, then rerun ./build.sh"
[[ -d "${STATE_DIR}/sessions" ]] || fail "state directory was not initialized" "check permissions for ${STATE_DIR}"
docker image inspect aegis-agent:v1 aegis-runtime:v1 aegis-proxy:v1 >/dev/null || fail "required Docker images are missing" "inspect the preceding image-build error"
docker network inspect "$BOOTSTRAP_NETWORK" >/dev/null || fail "AEGIS bootstrap network is missing" "rerun ./build.sh"
docker run --rm --network none aegis-runtime:v1 pip-audit --version >/dev/null || fail "pip-audit is unavailable in the runtime image" "inspect the agent image build output"
docker run --rm --network none aegis-runtime:v1 npm --version >/dev/null || fail "npm is unavailable in the runtime image" "inspect the agent image build output"

printf 'Running real sandbox smoke test...\n'
SMOKE_DIR=$(mktemp -d "${STATE_DIR}/smoke.XXXXXX")
trap 'rm -rf "$SMOKE_DIR"' EXIT
"$CLI" run --project "$SMOKE_DIR" --ui none true
printf '\nAEGIS READY\n'
printf 'Run: %s run <AI_AGENT> [ARGS...]\n' "$CLI"
printf 'Remove: %s/remove.sh\n' "$ROOT_DIR"
