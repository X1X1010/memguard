#!/usr/bin/env bash
# Summarize memguard activity and kernel memory events. Read-only.
# Usage: incident-report.sh [--since "6 hours ago"]   (default: 1 day ago)
set -uo pipefail
SINCE="1 day ago"
[ "${1:-}" = "--since" ] && [ -n "${2:-}" ] && SINCE="$2"
BIN=$(command -v memguard || echo /home/admin/storage/software/mem-guard/target/release/memguard)
echo "== memguard service"
systemctl --no-pager --lines=0 status memguard 2>&1 | sed -n '1,4p'
echo; echo "== current status ($BIN)"
"$BIN" status --top 5 2>&1 | head -20
echo; echo "== memguard: level changes, kills and verification since $SINCE"
journalctl -u memguard --since "$SINCE" --no-pager -o short-iso 2>/dev/null \
  | grep -E 'KILL \(|would kill|level [A-Z]+ -> |verified|no measurable|uninterruptible|starting:|stopping|headroom:|no eligible victim|late tick' \
  | tail -60 | cut -c1-400
echo; echo "== kernel: driver NO_MEMORY, OOM kills, hung tasks since $SINCE (deduplicated)"
journalctl --since "$SINCE" --no-pager -o short-iso _TRANSPORT=kernel 2>/dev/null \
  | grep -E 'NV_ERR_NO_MEMORY|Out of memory|Killed process|blocked for more than' \
  | sed -E 's/^([0-9T:+-]+) [^ ]+ kernel: /\1 /' | awk '!seen[substr($0,20)]++' | tail -30 | cut -c1-300
