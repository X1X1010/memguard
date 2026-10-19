# memguard configuration keys

File: `/etc/memguard/memguard.conf`, `key = value`, `#` comments. Sizes accept `8G`, `512M`, `5%`
(of MemTotal); durations `150ms`, `2s`; fractions `0.30` or `30%`. Lists: `[a, b*]`; list keys add to
the builtin defaults and `!entry` removes a builtin. `memguard check-config` prints effective values.
Keys marked (restart) need `systemctl restart`; everything else applies on `systemctl reload` (SIGHUP).

## Sampling
- `interval_ms` = 50 (restart): decision tick. 50 ms is 1.7 GiB per tick at the measured 34 GiB/s burst.
- `scan_interval_ms` = 2000, `warn_scan_interval_ms` = 250 (restart): /proc scan cadence idle / in WARN.

## Thresholds (MemAvailable based)
- `floor` = 8G: CRITICAL below this. Keep ≥ two ticks of burst (3.4 GiB) plus driver reserve.
- `warn` = 16G: WARN below this (fast scanning, fast NVML polling, candidate logging).
- `horizon_ms` = 150: kill when MemAvailable is projected to cross the floor within this time.
- `rate_ema_ms` = 200: smoothing of the consumption rate; the raw last-tick rate is also used.
- `rate_min` = 1G (per second): projection ignores slower drains.
- `rate_warn` = 4G (per second): any drain this fast enters WARN.

## Pressure stall information (PSI, `/proc/pressure/memory`)
- `psi_window_ms` = 1000: window for the stall fractions.
- `psi_full_critical` = 0.30: thrash trigger (two consecutive ticks), independent of MemAvailable.
- `psi_full_emergency` = 0.60: bypass debounce and cooldown.
- `psi_some_warn` = 0.20: WARN trigger.

## Swap
- `swap_rate_critical` = 512M (per second): swap growth combined with low MemAvailable or PSI.
  Absolute swap usage never triggers: it is state, not an event.

## Headroom controller (GB10 specific)
- `headroom` = 4G: keep at least this much MemFree by dropping file cache via root `memory.reclaim`
  with `swappiness=0` (never swaps). The driver needs truly free pages, not reclaimable cache.
- `headroom_reclaim` = true (restart).

## Actions
- `action` = kill | dry-run (restart to switch from dry-run to kill).
- `signal` = KILL | TERM, `grace_ms` = 0: with TERM, SIGKILL follows after the grace.
- `kill_mode` = auto | process | tree | cgroup. `auto` uses `cgroup.kill` for allow-listed scopes,
  otherwise the process tree; trees containing a protected process shrink to the single victim.
- `cgroup_kill_match` = [docker-*.scope, libpod-*.scope, cri-containerd-*.scope, memguard-*.scope].
- `stop_unit_after_kill` = true: `systemctl stop` a system service after killing its process so
  `Restart=` cannot relaunch the same job into the same crash.

## Kill gating
- `debounce_ticks` = 2, `cooldown_ms` = 2000, `emergency_cooldown_ms` = 500.
- `verify_ms` = 5000: window to see the victim gone and memory back.
- `backoff_ms` = [10000, 30000, 60000]: after a kill with no effect.
- `max_kills_per_min` = 3, `max_kills_per_10min` = 6.
- `min_victim` = 512M: never kill anything smaller.

## Victim selection
- `never_exe` (builtin: systemd, systemd-*, (sd-pam), init, sshd, dbus-*, memguard), `never_cgroup` = [/init.scope].
- `avoid_exe` (builtin: Xorg, Xwayland, gnome-shell, gdm*, mutter*, tmux*, dockerd, containerd*, tailscaled,
  NetworkManager, pipewire*, wireplumber, nvidia-persistenced, shells...): score × 0.5.
- `prefer_exe` = []: score × 2, e.g. `[python*, ollama*]`.
- `immune_override_pct` = 50: kill an `oom_score_adj=-1000` process anyway if it is the top GPU holder
  with ≥ this % of RAM in a fresh NVML sample; `off` disables.
- `shmem_weight` = 0.5, `growth_weight` = 2.0: footprint = GPU + anon + shmem_weight·shmem + swap;
  score = (tree footprint + growth_weight × growth/s) × weight.
- `cuda_file_rss_weight` = 0: fraction of a CUDA process's file-backed RSS to count. GPU-populated
  `cudaMallocManaged` pages live there (NVML does not report them), but so do shared libraries and
  mmapped model files; set 1.0 only for managed-memory workloads.
- `vidmem_charged` = auto | yes | no: whether the driver charges GPU pages to the allocating cgroup
  (`auto` behaves as `no`; verify with `memguard doctor --probe` before setting `yes`).

## Misc
- `status_file` = /run/memguard/status (restart), `log_level` = info, `mlock` = true (restart),
  `allow_coexist` = false (restart), `allow_huge_floor` = false (tests only), `only_kill_exe` (restart,
  test mode), `record` (restart, trace CSV path), `startup_grace_ticks` = 5.
