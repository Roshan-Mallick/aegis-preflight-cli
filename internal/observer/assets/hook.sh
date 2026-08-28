#!/bin/sh
LOG="${AEGIS_HOOK_LOG:-/workspace/.aegis/raw/hooks.jsonl}"
mkdir -p "$(dirname "$LOG")"
line=$(cat)
[ -n "$line" ] && printf '%s\n' "$line" >> "$LOG"
exit 0
