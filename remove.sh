#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR=${AEGIS_STATE_DIR:-"${HOME}/.local/state/aegis"}
BOOTSTRAP_NETWORK=${AEGIS_BOOTSTRAP_NETWORK:-aegis-bootstrap}
CLI_PATH_FILE="${STATE_DIR}/.aegis-cli-path"
PROXY_DIR_FILE="${STATE_DIR}/.aegis-proxy-dir"
CLI_PATH=$(cat "$CLI_PATH_FILE" 2>/dev/null || true)
PROXY_DIR=$(cat "$PROXY_DIR_FILE" 2>/dev/null || true)

remove_labeled() {
  local kind=$1
  local ids
  ids=$(docker "$kind" ls -aq --filter label=com.aegis.managed=true 2>/dev/null || true)
  if [[ -n "$ids" ]]; then
    docker "$kind" rm -f $ids
  fi
}

remove_legacy_named() {
  local kind=$1
  local pattern=$2
  local ids
  ids=$(docker "$kind" ls -aq --filter "name=${pattern}" 2>/dev/null || true)
  if [[ -n "$ids" ]]; then
    docker "$kind" rm -f $ids
  fi
}

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  remove_labeled container
  remove_legacy_named container '^aegis-agent-'
  remove_legacy_named container '^aegis-proxy-'
  networks=$(docker network ls -q --filter label=com.aegis.managed=true 2>/dev/null || true)
  if [[ -n "$networks" ]]; then
    docker network rm $networks
  fi
  legacy_networks=$(docker network ls --format '{{.ID}} {{.Name}}' | awk '$2 == "aegis-bootstrap" || $2 ~ /^aegis-net-/ {print $1}')
  if [[ -n "$legacy_networks" ]]; then
    docker network rm $legacy_networks
  fi
  for image in aegis-agent:v1 aegis-runtime:v1 aegis-proxy:v1; do
    managed=$(docker image inspect --format '{{index .Config.Labels "com.aegis.managed"}}' "$image" 2>/dev/null || true)
    if [[ "$managed" == true ]]; then
      docker image rm "$image"
    fi
  done
  volumes=$(docker volume ls -q --filter label=com.aegis.managed=true 2>/dev/null || true)
  if [[ -n "$volumes" ]]; then
    docker volume rm $volumes
  fi
else
  printf 'Docker unavailable; skipped Docker resources.\n' >&2
fi

# Only remove the generated config if this installation marked it as owned.
CONFIG_FILE="${ROOT_DIR}/aegis.json"
CONFIG_MARKER="${STATE_DIR}/.aegis-managed-config"
if [[ -f "$CONFIG_MARKER" ]]; then
  rm -f "$CONFIG_FILE" "$CONFIG_MARKER"
fi

state_cleanup=0
if [[ -f "${STATE_DIR}/.aegis-managed-state" ]]; then
  if ! rm -rf "$STATE_DIR"; then
    state_cleanup=1
  fi
elif [[ -d "$STATE_DIR" ]]; then
  # An unmarked state root may predate this installation. Remove only
  # individually marked AEGIS children and preserve everything else.
  while IFS= read -r -d '' session_dir; do
    rm -rf "$session_dir"
  done < <(find "${STATE_DIR}/sessions" -mindepth 1 -maxdepth 1 -type d -name '*' -exec sh -c 'for d do test -f "$d/.aegis-managed-session" && printf "%s\0" "$d"; done' sh {} + 2>/dev/null)
  for managed_dir in "${STATE_DIR}/bin" "${STATE_DIR}/cache" "${STATE_DIR}/tmp" "${STATE_DIR}/sessions"; do
    if [[ -f "${managed_dir}/.aegis-managed" ]]; then
      rm -rf "$managed_dir"
    fi
  done
  rm -f "${STATE_DIR}/.aegis-managed-config"
fi
rm -f "${ROOT_DIR}/aegis" "${ROOT_DIR}/aegis-proxy"
if [[ -n "$CLI_PATH" && "$CLI_PATH" != /usr/bin/* && "$CLI_PATH" != /usr/local/bin/* ]]; then
  rm -f -- "$CLI_PATH"
fi
if [[ -n "$PROXY_DIR" && -d "$PROXY_DIR" && -f "${PROXY_DIR}/aegis-proxy" ]]; then
  rm -rf -- "$PROXY_DIR"
fi

if [[ -f "${ROOT_DIR}/.aegis/.aegis-managed" ]]; then
  rm -f "${ROOT_DIR}/.aegis/bin/hook.sh" "${ROOT_DIR}/.aegis/.aegis-managed"
  rmdir "${ROOT_DIR}/.aegis/bin" "${ROOT_DIR}/.aegis/raw" "${ROOT_DIR}/.aegis" 2>/dev/null || true
fi
if [[ -f "${ROOT_DIR}/.claude/.aegis-managed" ]]; then
  if [[ -f "${ROOT_DIR}/.claude/settings.json.aegis-backup" ]]; then
    mv "${ROOT_DIR}/.claude/settings.json.aegis-backup" "${ROOT_DIR}/.claude/settings.json"
  else
    rm -f "${ROOT_DIR}/.claude/settings.json"
  fi
  rm -f "${ROOT_DIR}/.claude/.aegis-managed"
  rmdir "${ROOT_DIR}/.claude" 2>/dev/null || true
fi
if [[ -f "${ROOT_DIR}/.opencode/.aegis-managed" ]]; then
  if [[ -f "${ROOT_DIR}/.opencode/plugins/aegis.js.aegis-backup" ]]; then
    mv "${ROOT_DIR}/.opencode/plugins/aegis.js.aegis-backup" "${ROOT_DIR}/.opencode/plugins/aegis.js"
  else
    rm -f "${ROOT_DIR}/.opencode/plugins/aegis.js"
  fi
  rm -f "${ROOT_DIR}/.opencode/.aegis-managed"
  rmdir "${ROOT_DIR}/.opencode/plugins" "${ROOT_DIR}/.opencode" 2>/dev/null || true
fi
if [[ "$state_cleanup" -ne 0 ]]; then
  printf 'AEGIS removal incomplete: state directory contains files you cannot remove (%s).\n' "$STATE_DIR" >&2
  exit 1
fi
printf 'AEGIS removed.\n'
