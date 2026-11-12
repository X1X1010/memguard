# memguard — memory watchdog for NVIDIA GB10 (DGX Spark)

GB10 uses shared CPU/GPU system memory. A runaway GPU allocation can exhaust host RAM and cause
severe reclaim stalls, including loss of SSH and desktop responsiveness. memguard watches system
memory, pressure stall information (PSI), and NVIDIA per-process memory usage at a default 50 ms
interval. It attempts to reclaim file cache and terminate large memory consumers before the host
stalls. It also runs individual jobs under GPU/memory budgets (`memguard run`). This is a userspace
backstop, not a guarantee against kernel or driver hangs.

Rust, no runtime dependencies besides `libc`; NVML and libcuda are `dlopen`ed when present.

## Prior GB10 observations (original implementation, driver 580.159.03)

The measurements and journal history below came with the original implementation. They have not
been reproduced by the regression suite. Accounting and allocation behavior depend on the kernel,
driver, and allocation API; measure the installed stack before relying on these observations.

| Fact | Consequence |
|---|---|
| `cudaMalloc` / `cuMemCreate` / `cuMemAllocAsync` memory is eager and **invisible to the kernel**: process RSS, `oom_score` and cgroup `memory.current` do not change; only `MemFree`/`MemAvailable` drop | cgroup `MemoryMax` cannot bound it; the RSS-ranked kernel OOM killer kills innocent processes; systemd-oomd, earlyoom and nohang would too |
| NVML's per-process lists (`nvmlDeviceGetComputeRunningProcesses_v3`) report the bytes correctly in 16 µs, although device-level NVML memory is "Not Supported" | the only attribution path; cheap |
| NVML **blocks for the whole duration of another process's allocation ioctl** (715 ms measured for 24 GiB) | memguard runs NVML in a separate helper process and never lets it stall the decision loop |
| `VmSize` grows by the allocation size (the real hogs in this machine's journal had 155–272 GiB VmSize with ~30 MiB RSS) | VmSize + open `/dev/nvidia*` descriptors provides a heuristic fallback while NVML is stale |
| Allocation bursts run at ~34 GiB/s; 32 GiB come back ~430 ms after SIGKILL | 50 ms tick, rate projection, kill → verify → cooldown |
| The driver allocates with `__GFP_RETRY_MAYFAIL`: an oversize `cudaMalloc` never invokes the kernel OOM killer itself, it reclaims and swaps hard first | this is the "freeze": minutes of thrash, then driver allocations fail with `NV_ERR_NO_MEMORY` |
| The original analysis describes failures with **MemFree ≈ 1 GB while MemAvailable ≈ 103 GB** (98 GB page cache) | memguard requests root `memory.reclaim` with `swappiness=0`; actual free headroom is not guaranteed |
| Managed pages appeared in RSS and pinned host allocations in shmem on this stack | footprint uses NVML + anon + ½·shmem + swap; virtual UVM reservations are excluded; GPU-populated managed pages (RssFile) count only with `cuda_file_rss_weight`; sharing can still overcount |
| Driver/kernel changes can charge GPU pages to the allocating cgroup | `vidmem_charged=auto` conservatively adds GPU usage; set `yes` only after measurement with `memguard doctor --probe` |

This machine's journal: on 2026-10-11 the kernel killed dbus, `systemd --user`, gnome-shell, Xorg and
tailscaled in one second while the PyTorch hog had 0 kB anon RSS and 272 GiB VmSize; on 2026-10-17
the driver reported `NV_ERR_NO_MEMORY` for ten minutes before the first kernel OOM kill and the box
stayed "alive but useless" for 51 minutes.

## How it works

```
memguard daemon (root, SCHED_FIFO, mlockall)              memguard nvml-helper (child process)
 hot thread, 50 ms ticks from cached fds:                   dlopen libnvidia-ml, per-process GPU bytes
 /proc/meminfo, /proc/vmstat (nr_free_pages_blocks),  <--   pipe snapshots, with query age tracking
 /proc/pressure/memory  -> engine -> victim -> kill
 scan thread: /proc/<pid>/{status,stat,cgroup,exe,fd} (2 s; 250 ms in WARN)
 reclaim thread: root memory.reclaim "<bytes> swappiness=0" when MemFree < headroom
 output thread: bounded queue for status and trace writes; drops diagnostics if storage stalls
```

Decision engine (defaults, all configurable):

* **floor** — CRITICAL when `MemAvailable < 8 GiB`.
* **projection** — CRITICAL when `MemAvailable − rate × 150 ms < floor` and the drain is ≥ 1 GiB/s.
  At 34 GiB/s this fires at ≈ 13 GiB available; slower loads that stop above that are never touched.
* **thrash** — CRITICAL when PSI memory `full` ≥ 30 % over the last second, regardless of MemAvailable.
* **swap storm** — swap growing ≥ 512 MiB/s together with low MemAvailable or PSI. Absolute swap usage
  is never a trigger (it is state, not an event).
* WARN below 16 GiB, on PSI `some` ≥ 20 %, or while memory drains faster than 4 GiB/s: faster
  scanning, fast NVML polling and candidate logging.
* Kill gating: 2-tick debounce (bypassed in emergency: avail < floor/2 or PSI full ≥ 60 %), 2 s
  cooldown, a 5 s verification window (victim gone and memory back), exponential backoff when a kill
  had no effect, hard caps of 3 kills/min and 6 kills/10 min, startup grace.

Victim selection: `footprint = GPU bytes + RssAnon + 0.5·RssShmem + VmSwap`, aggregated over eligible
process trees; `score = (footprint + 2 × growth/s) × weight`, with
`weight` from `oom_score_adj` and tiers: **never** (pid 1, kernel threads, systemd, sshd, dbus,
memguard itself, `init.scope`), **immune** (`oom_score_adj = -1000`, unless it is the top GPU holder
with ≥ 50 % of RAM in a fresh NVML sample), **avoid** (×0.5: display stack, docker/containerd, shells, tmux...), **prefer**,
and **preferred** (`oom_score_adj ≥ 900`, killed first). Matching uses the executable path and comm,
never `cmdline` or `maps` (which can block on a stuck task). Path patterns match the executable
path; bare patterns match its basename or comm.

Kill: open a `pidfd`, then check start time for every target, including descendants and later
SIGKILL escalation. There is no raw-PID fallback. Trees with protected descendants are reduced to
the selected process. `cgroup.kill` is used only for allowed scopes with no protected or newly
observed members; TERM always uses individual signals. Service stopping is allowed only when all
observed cgroup members pass protection checks, and is disabled in test mode. No synchronous
`process_mrelease` call runs in the decision loop. A silent helper is killed and replaced only once
it exits, so a stuck driver cannot accumulate helpers.

## Install

```sh
cargo build --release
sudo ./packaging/install.sh            # validate, install binaries/config/unit, enable and restart
sudo ./packaging/install.sh --sysctl   # additionally: /etc/sysctl.d/90-memguard.conf (kswapd headroom)
memguard doctor                        # environment checks; add --probe to measure cgroup charging
journalctl -fu memguard
```

Requirements: Linux ≥ 5.14 (cgroup v2, `cgroup.kill`, PSI), systemd (253+ for scope `OOMPolicy`). NVIDIA driver with NVML for
per-process attribution (otherwise VmSize heuristics only).

Measured idle overhead on this machine (50 ms tick, after the identity-check revisions): daemon ≈ 0.9 % of
one core (decision loop 0.4 %, /proc scan every 2 s 0.5 %) with 6 MiB resident and locked; NVML
helper ≈ 0.2 % and 20 MiB. In WARN/CRITICAL the scan runs every 250 ms and the helper polls every 50 ms.

## Getting it onto another DGX Spark

Requirements: DGX OS 7 / Ubuntu 24.04 on arm64 (any Linux ≥ 5.14 with cgroup v2, PSI and systemd works),
the NVIDIA driver with NVML (`libnvidia-ml.so.1`). The binaries depend only on glibc; no Rust or CUDA
toolkit is needed on the target machine.

```sh
# A. Debian package: enables and starts the service
sudo apt install ./memguard_0.1.0_arm64.deb

# B. Prebuilt tarball
tar xzf memguard-0.1.0-aarch64.tar.gz && cd memguard-0.1.0-aarch64 && sudo ./packaging/install.sh

# C. From source
git clone https://github.com/X1X1010/memguard.git && cd memguard && cargo build --release && sudo ./packaging/install.sh
```

Afterwards run `memguard doctor` (environment checks), `memguard status`, and watch
`journalctl -fu memguard`. The defaults are sized for the 128 GB GB10; adjust
`/etc/memguard/memguard.conf` and `systemctl reload memguard` if needed. The daemon refuses to run next to
systemd-oomd or earlyoom, so disable those first (or set `allow_coexist = true` knowingly). Claude Code users
can link `skills/memguard` (or `/usr/share/memguard/skills/memguard` from the package) into `~/.claude/skills/`.
Maintainers build the artifacts with `packaging/build-deb.sh` and `packaging/build-release.sh`.

## Usage

```
memguard daemon  [--config F] [--dry-run] [--only-kill-exe PATH] [--record F] [-o key=value]...
memguard run     [--gpu SZ] [--mem SZ] [--total SZ] [--swap SZ|max] [--floor SZ]
                 [--prefer-kill | --oom-adj N] [--unit NAME] [--no-scope] [--dry-run] -- CMD ARGS...
memguard status  [--json] [--top N]      memguard ps [--sort footprint|vidmem|rss|swap|vmsize] [-n N]
memguard doctor  [--probe]               memguard check-config [--config F] [-o key=value]...
memguard replay  TRACE [-o key=value]... memguard version
```

### Protected execution

```sh
memguard run --gpu 60G -- python train.py                 # SIGKILL the job above 60 GiB of GPU memory
memguard run --mem 16G --swap 0 -- python preprocess.py   # kernel-enforced RAM budget, no swap
memguard run --total 90G --prefer-kill -- vllm serve ...  # GPU + RAM budget; preferred victim system-wide
```

The job runs in a transient systemd scope (`systemd-run --user --scope`, no root needed). `--mem`
becomes `MemoryMax` (kernel enforced; the scope carries `OOMPolicy=kill` so the whole job dies). `--gpu` and
`--total` are enforced by memguard every 50 ms because the kernel cannot see GPU memory on this
driver; `--total` counts anon + shmem + kernel + swap from `memory.stat` (not page cache) plus GPU
bytes. With explicitly verified `vidmem_charged=yes`, cgroup usage includes GPU allocations and
the total is at least the observed GPU usage. Without a scope, GPU bytes are always added to RSS.
Exit status is the job's, or 137 when termination is requested for a budget violation. The job is
sacrificed on the system floor only when no active enforcing daemon is running and it holds ≥ 25 % of RAM or is the top
GPU holder. Docker containers escape scopes; give them budgets with `docker run --memory` plus the
daemon, or `--cgroup-parent=some.slice`.

GPU/total budgets require working NVML before launch (the job is not started otherwise). If the
telemetry later goes stale (NVML blocks while any process is inside a large allocation), the budget
is enforced against the last known value and a warning is logged; the job is never killed for
missing telemetry, and a vanished cgroup file is never treated as a violation. `--dry-run` reports
violations without setting `MemoryMax`, `MemorySwapMax`, or `OOMPolicy=kill`, and the daemon's dry-run
mode does not reclaim memory. Normal scope execution disables swap by default; `--swap max` permits it.

### Testing with bounded allocations

`cargo test --all-targets` uses synthetic pressure traces and disposable children, including a
32 MiB anonymous-memory budget test. It does not deliberately exhaust system memory.

`memguard-hog` allocates GPU/managed/pinned/anonymous memory at a controlled rate, sets its own
`oom_score_adj=1000`, refuses to drop MemAvailable below `--min-avail` (32 GiB) and caps itself at
`--max` (40 GiB). `scripts/safe-test.sh` runs the budget, dry-run and test-mode scenarios with a floor
24 GiB below the current MemAvailable; `sudo scripts/safe-test.sh root` adds a root kill restricted
to that test binary. All daemon stress tests restrict the executable and disable cache reclaim.
These GPU stress tests still allocate tens of GiB: use an otherwise idle machine. Concurrent jobs
can consume memory after the hog's availability check, so the check is not a system-wide reservation.
`--only-kill-exe` also restricts descendants and disables whole-cgroup kills and service stops.
`--record trace.csv` records each decision tick for `memguard replay trace.csv -o floor=...`; a
bounded output queue may drop records under storage pressure (counted in `log_dropped`).

## Configuration

`/etc/memguard/memguard.conf`, `key = value`; see `packaging/memguard.conf` for every key with its
default and `memguard check-config` for the effective values and which live processes the protect
rules match. `-o key=value` overrides on the command line. `SIGHUP` reloads thresholds.
CLI safety restrictions are reapplied on every reload. Changes to sampling intervals, output paths,
locking/reclaim setup, coexistence, executable restrictions, or enabling kills from dry-run require
a restart. Reloading `action=dry-run` disables further kills and pending escalation.

Tuning notes:

* `floor` must cover at least two ticks of the fastest burst (3.4 GiB) plus driver reserves; 8 GiB
  is conservative for a 128 GB desktop box. Raise `warn` if you want earlier candidate logging.
* `horizon_ms` trades false kills of fast legitimate loads against reaction margin; 150 ms (3 ticks)
  only kills loads that would cross the floor within the next 150 ms.
* `headroom` is the target for best-effort file-cache reclaim; raise it if
  you see `NV_ERR_NO_MEMORY` in `journalctl -k` while MemAvailable looks healthy.
* Prefer `prefer_exe = [python*, ollama*]` over lowering protections; shells, display and system
  services are only avoided, not immune, so a desperate situation still resolves.
* Frameworks size themselves from `cudaMemGetInfo`, which reports `MemFree` as free: vLLM's default
  `gpu_memory_utilization=0.9` tries to take ~108 GiB on this box. Lower it; memguard is the backstop,
  not the budget.

## Limitations

* A task in an uninterruptible driver operation may not exit promptly after SIGKILL. Cache reclaim
  cannot guarantee recovery, and a polling watchdog can miss an allocation burst. Keep workload
  limits below physical RAM and leave headroom for the OS and allocation/teardown latency.
* Without NVML, daemon attribution falls back to VmSize heuristics for processes with NVIDIA device
  descriptors. Virtual address reservations can substantially overestimate actual GPU usage.
* Memory shared between processes (CUDA IPC, `/dev/shm`) is attributed to every holder; verification
  and backoff keep this from cascading.
* `memguard run` rejects GPU/total budgets in a detected nested PID namespace. Namespace detection
  depends on the mounted procfs view; use host execution for reliable GPU attribution.
* `--no-scope` and automatic fallback use sampled process-tree accounting. They cannot enforce
  `--swap`, do not supply kernel `MemoryMax`, and can miss children that fork and detach between scans.
* Process protection is based on snapshots. Membership and executable changes concurrent with a
  cgroup kill or service stop cannot be made atomic with userspace checks.
* The daemon refuses to run next to systemd-oomd/earlyoom/nohang (`allow_coexist = true` to override).

The interface semantics used here are documented by the [Linux cgroup v2 guide](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
[NVIDIA NVML reference](https://docs.nvidia.com/deploy/nvml-api/latest/api/group__nvmlDeviceQueries.html),
and [systemd execution settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

## Files

`src/engine.rs` decision engine · `src/victim.rs` selection · `src/sys/*` /proc, cgroup, NVML, CUDA
readers · `src/helper.rs` NVML helper process · `src/daemon.rs`, `src/runner.rs` front-ends ·
`src/bin/memguard-hog.rs` load generator · `packaging/` unit, config, install scripts ·
`scripts/safe-test.sh` end-to-end tests.
