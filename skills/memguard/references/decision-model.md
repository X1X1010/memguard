# How memguard decides

## Measured GB10 facts that shape everything
- `cudaMalloc`, `cuMemCreate` and `cuMemAllocAsync` memory is eager and invisible to the kernel: RSS,
  `oom_score`, cgroup `memory.current` do not change; only MemFree/MemAvailable drop. cgroup
  `MemoryMax` cannot bound it; the kernel OOM killer kills innocents (this box: dbus, gnome-shell, Xorg).
- NVML per-process lists are the only attribution (16 µs per call) but block for the whole duration of
  any process's large allocation ioctl (715 ms for 24 GiB). Hence the separate `nvml-helper` process.
- Bursts reach ~34 GiB/s; 32 GiB returns ~430 ms after SIGKILL.
- The driver allocates with `__GFP_RETRY_MAYFAIL`: it never invokes the kernel OOM killer, it reclaims
  and swaps hard first, then fails with `NV_ERR_NO_MEMORY`. NVIDIA's own analysis shows failures with
  MemFree ≈ 1 GB while MemAvailable ≈ 103 GB, so MemFree headroom matters, not just MemAvailable.
- Managed memory shows as RssFile and is memcg-charged; pinned host memory is shmem. NVML counts neither.

## Levels (every 50 ms tick)
- CRITICAL when any of: MemAvailable < floor; MemAvailable − rate × horizon < floor with rate ≥ rate_min;
  PSI `full` ≥ psi_full_critical for two ticks; swap growth ≥ swap_rate_critical together with low
  MemAvailable or PSI `some` ≥ 0.30. Emergency (bypasses debounce/cooldown): MemAvailable < floor/2 or
  PSI `full` ≥ psi_full_emergency.
- WARN when MemAvailable < warn, PSI `some` ≥ psi_some_warn, MemFree < headroom, or drain ≥ rate_warn.
  WARN switches the /proc scan to 250 ms and the NVML helper to 50 ms polling.
- Kill gate: CRITICAL and debounced, no verification pending, cooldown elapsed, not in backoff, under
  the rate caps (3/min, 6/10 min), past the 5-tick startup grace.

## Victim
footprint = GPU bytes (NVML; VmSize-based estimate while NVML is stale for CUDA processes) + RssAnon
+ shmem_weight·RssShmem + VmSwap (+ cuda_file_rss_weight·RssFile for CUDA processes). Trees aggregate
descendants unless a descendant is protected. score = (tree footprint + growth_weight × growth/s) ×
weight, weight from oom_score_adj and tier (avoid ×0.5, prefer ×2; adj ≥ 900 is killed first;
adj = −1000 only via immune_override). Every target is identified by PID plus start time; a reused PID
is never signalled.

## After a kill
Verification window (5 s): success = victim gone and MemAvailable up by ≥ 30 % of its footprint, or the
level dropped below CRITICAL. No effect → exponential backoff (10/30/60 s). Victim alive in D state →
"stuck" (likely wedged in the driver). A repeat kill of the same exe+cgroup within 10 minutes starts the
backoff immediately. System services are `systemctl stop`ped so `Restart=` cannot loop.

## Log lines worth grepping (`journalctl -u memguard`)
- `memguard ... starting: total=... floor=... warn=...` effective configuration at start.
- `level OK -> WARN (...)`, `level WARN -> CRITICAL (reasons=projection ...)`: transitions with metrics.
- `top candidate: pid=... comm=... fp=... (vid=... anon=...)`: who would die right now (WARN only).
- `KILL (reasons; avail=...) via tree: pid=... plan=Tree([...]) signaled=[...]`: an actual kill.
- `DRY-RUN would kill` / `TEST-MODE would kill`: not in kill mode.
- `kill of pid N verified: avail X -> Y (ms)`, `had no measurable effect`, `still alive in
  uninterruptible sleep`: verification outcomes.
- `headroom: free=... reclaiming ...`: headroom controller activity.
