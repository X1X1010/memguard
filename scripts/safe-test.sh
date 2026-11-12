#!/usr/bin/env bash
# End-to-end tests with bounded allocations; run on an otherwise idle machine.
#   ./scripts/safe-test.sh            unprivileged tests (run budgets, daemon dry-run, test-mode kill)
#   sudo ./scripts/safe-test.sh root  additionally: root daemon kill restricted to this test's hog binary
# Safety: the hog refuses to allocate below --min-avail (32 GiB) and daemon tests use a floor
# 24 GiB below the current MemAvailable. Other workloads can still consume memory concurrently.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
B="$ROOT/target/release"
[ -x "$B/memguard" ] || B="$ROOT/bin"
MODE="${1:-user}"
RT=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/memguard-test.XXXXXX")
DP=""
cleanup() {
  if [ -n "$DP" ]; then
    kill -TERM "$DP" 2>/dev/null || true
    wait "$DP" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
PASS=0; FAIL=0
ok()   { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
avail_g() { awk '/MemAvailable/{printf "%d", $2/1048576}' /proc/meminfo; }

[ -x "$B/memguard" ] && [ -x "$B/memguard-hog" ] || { echo "no binaries: cargo build --release, or run from an extracted release tarball"; exit 1; }
HOG="$RT/memguard-hog"
cp "$B/memguard-hog" "$HOG"
AV=$(avail_g)
[ "$AV" -ge 60 ] || { echo "need >= 60 GiB MemAvailable (have ${AV}G)"; exit 1; }
FLOOR=$((AV-24)); WARN=$((AV-16))
echo "MemAvailable ${AV}G -> test floor ${FLOOR}G warn ${WARN}G"
DOPTS=(--config /dev/null --only-kill-exe "$HOG" -o "floor=${FLOOR}G" -o "warn=${WARN}G" -o allow_huge_floor=true -o headroom_reclaim=false -o "status_file=$RT/status")

echo "[A] run --gpu 4G vs 8G vidmem hog"
timeout 90 "$B/memguard" run --gpu 4G -- "$HOG" --vidmem 8G --step 1G --rate 2 --hold 5 --quiet >"$RT/a.log" 2>&1
rc=$?; grep -q "GPU budget 4.0G exceeded" "$RT/a.log" && [ $rc = 137 ] && ok "killed at >4G (exit 137)" || bad "rc=$rc $(tail -2 "$RT/a.log")"

echo "[B] run --mem 1G vs 2G anon hog (kernel memcg OOM inside the scope)"
timeout 90 "$B/memguard" run --mem 1G -- "$HOG" --anon 2G --step 256M --hold 3 --quiet >"$RT/b.log" 2>&1
rc=$?; grep -Eq "memcg OOM|OOM is possible|memory budget" "$RT/b.log" && [ $rc = 137 ] && ok "memory limit terminated the job (exit 137)" || bad "rc=$rc $(tail -2 "$RT/b.log")"

echo "[C] run --total 3G vs 2 children x 2G vidmem (cgroup.kill, no leftovers)"
timeout 90 "$B/memguard" run --total 3G -- "$HOG" --vidmem 4G --children 2 --step 512M --rate 2 --hold 5 --quiet >"$RT/c.log" 2>&1
rc=$?; sleep 1; left=0
for pid in $(pgrep -x memguard-hog || true); do
  [ "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" != "$HOG" ] || left=$((left+1))
done
grep -q "total budget 3.0G exceeded" "$RT/c.log" && [ $rc = 137 ] && [ "${left:-0}" = 0 ] && ok "whole scope killed" || bad "rc=$rc leftovers=$left"

echo "[D] run --dry-run --gpu 2G (hog completes)"
timeout 90 "$B/memguard" run --dry-run --gpu 2G -- "$HOG" --vidmem 4G --step 1G --rate 4 --hold 1 --quiet >"$RT/d.log" 2>&1
rc=$?; grep -q "DRY-RUN would kill" "$RT/d.log" && [ $rc = 0 ] && ok "reported, not killed" || bad "rc=$rc"

echo "[E] daemon --dry-run, hog 30G"
"$B/memguard" daemon --dry-run "${DOPTS[@]}" >"$RT/e.log" 2>&1 & DP=$!; sleep 1.5
"$HOG" --vidmem 30G --step 1G --rate 10 --hold 4 --quiet; hrc=$?
sleep 1; kill -TERM $DP; wait "$DP"; DP=""
grep -q "would kill" "$RT/e.log" && grep -q "memguard-hog" "$RT/e.log" && [ $hrc = 0 ] && ok "named the hog, did not kill" || bad "hog rc=$hrc; $(grep -c 'would kill' "$RT/e.log") would-kill lines"

echo "[F] daemon --only-kill-exe memguard-hog (real kill, test mode), hog 30G"
"$B/memguard" daemon --only-kill-exe memguard-hog "${DOPTS[@]}" >"$RT/f.log" 2>&1 & DP=$!; sleep 1.5
"$HOG" --vidmem 30G --step 1G --rate 10 --hold 20 --quiet 2>/dev/null; hrc=$?
sleep 3; kill -TERM $DP; wait "$DP"; DP=""
grep -q "KILL (" "$RT/f.log" && grep -q "verified" "$RT/f.log" && [ $hrc = 137 ] && ok "hog killed (exit 137) and recovery verified" || bad "hog rc=$hrc $(grep -E 'KILL|verified' "$RT/f.log" | head -2)"

echo "[G] daemon --dry-run: innocent 8G anon hog below the floor is left alone"
"$B/memguard" daemon --dry-run "${DOPTS[@]}" >"$RT/g.log" 2>&1 & DP=$!; sleep 1.5
"$HOG" --anon 8G --step 1G --rate 4 --hold 2 --quiet; hrc=$?
sleep 1; kill -TERM $DP; wait "$DP"; DP=""
! grep -q "would kill" "$RT/g.log" && [ $hrc = 0 ] && ok "no kill decision for an in-budget job" || bad "unexpected would-kill"

if [ "$MODE" = root ]; then
  [ "$(id -u)" = 0 ] || { echo "root mode needs sudo"; exit 1; }
  echo "[H] root daemon, restricted to the test hog, 30G"
  "$B/memguard" daemon "${DOPTS[@]}" -o allow_coexist=true >"$RT/h.log" 2>&1 & DP=$!; sleep 1.5
  "$HOG" --vidmem 30G --step 1G --rate 10 --hold 20 --quiet 2>/dev/null; hrc=$?
  sleep 3; kill -TERM $DP; wait "$DP"; DP=""
  grep -q "KILL (" "$RT/h.log" && grep -q "comm=memguard-hog" "$RT/h.log" && [ $hrc = 137 ] && ok "root kill of the hog" || bad "hog rc=$hrc"
fi

echo "== $PASS passed, $FAIL failed (logs in $RT)"
[ $FAIL = 0 ]
