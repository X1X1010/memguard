---
name: memguard
description: Operate memguard, the unified-memory watchdog for this NVIDIA DGX Spark (GB10) that lives in /home/admin/storage/software/mem-guard. Covers installing or upgrading the service, checking health and who holds GPU memory, running training/inference jobs under GPU or RAM budgets (`memguard run`), tuning thresholds, running the safe tests, and diagnosing kills or freezes. Use this skill whenever Aibo mentions memguard, a memory watchdog, OOM protection or "the box froze/hung", wants a GPU or memory limit for a job (vLLM, Ollama, PyTorch, llama.cpp), asks what is eating RAM or GPU memory, or notes that nvidia-smi shows N/A memory on this machine, even when the word memguard is not used.
---

# memguard on the DGX Spark

memguard exists because GB10 has no separate GPU memory: every `cudaMalloc` is system RAM that the
kernel cannot attribute to a process (RSS, memcg and the kernel OOM killer are blind to it; `nvidia-smi`
shows "N/A"). A runaway job therefore freezes the whole machine instead of getting a CUDA OOM error, and
this box has done exactly that three times. memguard watches MemAvailable at 50 ms, asks the NVIDIA
Management Library (NVML) which process holds GPU memory, keeps free headroom, and kills the right job
before the freeze. Read `README.md` in the repo for the measured facts when a decision depends on them.

## Where things are

| What | Path |
|---|---|
| Repo (git, Rust, `cargo build --release`) | `/home/admin/storage/software/mem-guard` |
| Binaries when installed / when not | `/usr/local/sbin/memguard`, `memguard-hog` / `target/release/` |
| Config (key = value, defaults in `packaging/memguard.conf`) | `/etc/memguard/memguard.conf` |
| Service unit | `memguard.service` (`journalctl -u memguard`) |
| Daemon status file (read by `memguard status`) | `/run/memguard/status` |
| Safe end-to-end tests | `scripts/safe-test.sh` (unprivileged), `sudo scripts/safe-test.sh root` |

Start every task with `memguard status` and `memguard doctor`: they tell you whether the daemon runs,
in which mode (kill, DRY-RUN or TEST-MODE), whether NVML works, and what the thresholds are. Do not
assume the service is installed because someone said so; `systemctl status memguard` is the truth.

## Rules that keep this machine alive

- Never run an experiment that approaches real memory exhaustion. Aibo works over SSH; a freeze means
  a physical reboot. Use `memguard-hog` only with its guards (`--min-avail 32G`, `--max 40G`) and
  daemon tests only with a floor far above real danger, the way `scripts/safe-test.sh` does.
- Anything needing root (install, root tests, editing `/etc/memguard`) must be typed by Aibo in one of
  their own terminals. `sudo` has no TTY inside Claude Code's `!` prefix and fails to read the password.
  Give the exact command and ask them to run it.
- Prefer `--dry-run` and `--only-kill-exe <path>` when testing daemon behaviour: dry-run only logs,
  test mode kills nothing but the named executable.
- Do not loosen protections to make a job fit. Lower the job's own appetite instead (vLLM
  `--gpu-memory-utilization`, batch size, context length); memguard is the backstop, not the budget.
- Do not commit to the repo unless Aibo asks; when they do, commits carry the usual attribution trailer.

## Common tasks

### Is everything healthy? What is eating memory?

```sh
memguard status                    # avail/free/headroom, PSI, NVML, daemon mode, top processes
memguard ps --sort vidmem -n 15    # per-process GPU bytes (NVML) + anon/shmem/swap/VmSize/tier
memguard doctor                    # environment checks; add --probe to measure cgroup charging
systemctl status memguard --no-pager && journalctl -u memguard -n 50 --no-pager
```

The `GPU` column is the only reliable per-process GPU figure on this box. A `~` after it means an
estimate from VmSize because NVML was stale. `TIER` shows how the daemon treats the process
(`never`, `avoid`, `normal`, `prefer`, `preferred`, `immune`). The `driver/other (est.)` line in
`status` is total memory held by the GPU driver that no kernel counter attributes.

### Run a job under a budget (no root needed)

```sh
memguard run --gpu 60G -- python train.py                 # SIGKILL above 60 GiB of GPU memory
memguard run --mem 16G --swap 0 -- python preprocess.py   # kernel-enforced RAM limit, no swap
memguard run --total 90G --prefer-kill -- vllm serve ...  # GPU + RAM together; preferred victim
memguard run --dry-run --gpu 40G -- ./job                 # observe peak usage without killing
```

The job runs in a transient systemd scope. `--mem` is enforced by the kernel (MemoryMax, whole scope
dies). `--gpu` and `--total` are enforced by memguard every 50 ms because the kernel cannot see GPU
memory. Exit status is the job's own, or 137 with a line starting `memguard: KILLED` naming the
budget that was exceeded and the peak usage, which is also the best way to size a budget: run once
with `--dry-run`, read `peak gpu=... mem=...`, then set budgets with 10–20 % slack. Docker
containers escape scopes; budget them with `docker run --memory` plus the daemon.

### Install, upgrade, remove

```sh
cd /home/admin/storage/software/mem-guard && cargo build --release && cargo test
sudo ./packaging/install.sh            # validate config, atomic binary replace, enable + restart
sudo ./packaging/install.sh --sysctl   # also raise kswapd free-memory watermarks (optional)
sudo ./packaging/uninstall.sh [--purge]
```

Upgrading is the same install command after a rebuild. Verify with `systemctl status memguard`,
`memguard doctor` and a look at `journalctl -u memguard -n 20` for the `starting:` line that prints the
effective floor, warn and headroom.

### Tune thresholds

Edit `/etc/memguard/memguard.conf` (root), validate, then reload or restart:

```sh
memguard check-config                      # prints effective values and which processes each rule matches
sudo systemctl reload memguard             # SIGHUP: thresholds, lists, weights
sudo systemctl restart memguard            # required for interval_ms, scan intervals, status_file, mlock, headroom_reclaim, action
```

Defaults and what to change for which symptom:

| Symptom | Knob (default) | Direction |
|---|---|---|
| Legit fast model loads get killed | `horizon_ms` (150), `floor` (8G) | lower horizon or floor slightly; or budget the job with `memguard run` |
| Box still thrashed before a kill | `floor` (8G), `warn` (16G), `psi_full_critical` (0.30) | raise floor/warn, lower PSI threshold |
| `NV_ERR_NO_MEMORY` in `journalctl -k` while MemAvailable looked fine | `headroom` (4G) | raise; consider `install.sh --sysctl` |
| Wrong process chosen | `prefer_exe` / `avoid_exe` / `never_exe` (globs on exe basename or comm) | bias explicitly; check with `memguard check-config` |
| Service with `Restart=always` relaunched into the same crash | `stop_unit_after_kill` (true) | keep on |
| Managed-memory (`cudaMallocManaged`) job never ranked | `cuda_file_rss_weight` (0) | set 1.0 for such workloads |
| Driver ≥ 590 double-counts GPU memory in `--total` | `vidmem_charged` (auto) | run `memguard doctor --probe`, set `yes` only if it reports charging |

The full key list with meanings is in `references/config-keys.md`; how the daemon decides (levels,
projection, verification, backoff) is in `references/decision-model.md`. Read them before changing
anything other than the table above.

### Investigate a kill or a freeze

```sh
bash /home/admin/storage/software/mem-guard/skills/memguard/scripts/incident-report.sh --since "6 hours ago"
```

The script gathers memguard level changes and `KILL (` lines, their `verified` / `no measurable
effect` / `stuck` follow-ups, and the kernel's own `NV_ERR_NO_MEMORY`, OOM-kill and hung-task lines.
A kill line names the reason (`floor`, `projection`, `thrash`, `swap-storm`), the victim with its
footprint components, and the plan (`Tree`, `Process`, `cgroup.kill`). `DRY-RUN would kill` or
`TEST-MODE would kill` means the daemon was not in kill mode. For threshold tuning, record a trace with
`-o record=/path/trace.csv` (or `--record`) and replay it offline:
`memguard replay trace.csv -o floor=10G -o horizon_ms=200`.

### Run the tests

```sh
cargo test && cargo clippy --all-targets -- -D warnings
./scripts/safe-test.sh                 # budgets, dry-run, test-mode kill; needs >= 60 GiB free
sudo ./scripts/safe-test.sh root       # adds a real root kill restricted to the test hog
```

`memguard-hog` is the load generator: `--vidmem/--managed/--pinned/--anon SIZE`, `--step`, `--rate`,
`--hold`, `--children N`; it sets its own `oom_score_adj=1000` and refuses to go below `--min-avail`.

## Troubleshooting

| Observation | Meaning / action |
|---|---|
| `memguard daemon` exits: "systemd-oomd.service is active" | two userspace killers would fight; disable the other or set `allow_coexist = true` knowingly |
| "another memguard daemon holds .../lock" | a daemon is already running (`pgrep -a memguard`) |
| `status` shows `daemon not running` though the service is active | check `status_file` path and `journalctl -u memguard`; the file is written once per second |
| `nvml unavailable` | driver not loaded or `libnvidia-ml.so.1` missing; attribution falls back to VmSize heuristics; `memguard run --gpu` refuses to start |
| `run`: "systemd-run --user --scope is not usable here" | no user bus (cron, `sudo -u`, containers); job is supervised as a process tree, `--mem` cannot be kernel-enforced |
| `run` warns "GPU telemetry stale" | NVML blocked while some process did a huge allocation; budgets use the last value, nothing is killed for this |
| Job killed with "system MemAvailable below floor (no daemon running)" | without a daemon, `run` sacrifices its own job when it holds ≥ 25 % of RAM or is the top GPU holder; install the daemon |
| Daemon logs "no eligible victim" while CRITICAL | everything big is `never`/`immune` or below `min_victim`; inspect `memguard ps` and the `never_exe`/`immune_override_pct` settings |
| "still alive in uninterruptible sleep after SIGKILL" | the process is wedged in the driver; memguard backs off; a reboot is likely needed |
