#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_ringbuf.py - Benchmark BPF_RINGBUF (Linux ≥ 5.8) event latency.
#
# Methodology:
#   Same probe/trigger as bench_perf_output but uses BPF_RINGBUF_OUTPUT
#   (a single shared ring buffer, more efficient than per-CPU perf buffers).
#   Allows direct apples-to-apples comparison with BPF_PERF_OUTPUT results.
#
#   On kernels < 5.8 the script exits cleanly with a skip message.
#
# Usage:
#   sudo python3 tests/bench_ringbuf/bench_ringbuf.py
#   sudo python3 tests/bench_ringbuf/bench_ringbuf.py --events 10000
#
# Output (stdout): single JSON object with benchmark metrics.

import argparse
import json
import os
import sys
import time
import ctypes as ct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from bench_utils import compute_stats, write_result, BenchmarkTimer

# ---------------------------------------------------------------------------
# Kernel version check — BPF_RINGBUF requires Linux 5.8+
# ---------------------------------------------------------------------------

def _kernel_version():
    """Return (major, minor) of the running kernel."""
    with open("/proc/version") as fh:
        version_str = fh.read().split()[2]   # e.g. "5.15.0-76-generic"
    parts = version_str.split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return 0, 0

major, minor = _kernel_version()
if (major, minor) < (5, 8):
    skip_result = {
        "benchmark": "bench_ringbuf",
        "transport": "BPF_RINGBUF",
        "skipped":   True,
        "reason":    "Kernel %d.%d < 5.8 — BPF_RINGBUF not available" % (major, minor),
    }
    print(json.dumps(skip_result))
    sys.exit(0)

from bcc import BPF

# ---------------------------------------------------------------------------
# eBPF (C) kernel program
# ---------------------------------------------------------------------------

BPF_PROGRAM = r"""
#include <linux/sched.h>

// Same event layout as bench_perf_output for a fair comparison.
struct event_t {
    u64 kernel_ts;   // bpf_ktime_get_ns() — kernel-side timestamp
    u32 pid;
};

// BPF_RINGBUF_OUTPUT declares a single shared ring buffer (not per-CPU).
// Unlike BPF_PERF_OUTPUT, it avoids per-CPU memory fragmentation and
// provides in-order delivery across CPUs.
// RINGBUF_PAGES is substituted at load time from the --ring-pages argument.
BPF_RINGBUF_OUTPUT(events, RINGBUF_PAGES);

int probe_getpid(struct pt_regs *ctx) {
    // ringbuf_reserve() allocates space in the ring buffer without copying —
    // we write directly into the reserved slot to avoid a double copy.
    struct event_t *ev = events.ringbuf_reserve(sizeof(struct event_t));
    if (!ev) {
        // Ring buffer full: drop this event rather than blocking.
        return 0;
    }

    ev->kernel_ts = bpf_ktime_get_ns();
    ev->pid       = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // ringbuf_submit() makes the slot visible to userspace consumers.
    events.ringbuf_submit(ev, 0);
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Python ctypes mirror of the kernel struct
# ---------------------------------------------------------------------------

class Event(ct.Structure):
    _fields_ = [
        ("kernel_ts", ct.c_uint64),
        ("pid",       ct.c_uint32),
    ]

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Benchmark BPF_RINGBUF kernel→userspace event latency."
)
parser.add_argument(
    "--events", "-n",
    type=int,
    default=10_000,
    help="Number of events to collect before reporting (default: 10000)",
)
parser.add_argument(
    "--ring-pages",
    type=int,
    default=64,
    help=(
        "Ring buffer size in pages (must be a power of 2, default: 64). "
        "Larger values reduce event drops when the consumer is slow."
    ),
)
parser.add_argument(
    "--output-dir",
    default=os.path.join(os.path.dirname(__file__), "..", "results"),
    help="Directory for .jsonl result files",
)
args = parser.parse_args()

TARGET_EVENTS = args.events

# ---------------------------------------------------------------------------
# State shared between the ring-buffer callback and the main loop
# ---------------------------------------------------------------------------

latencies_ns = []
done = False

# ---------------------------------------------------------------------------
# Load and attach BPF program
# ---------------------------------------------------------------------------

b = BPF(text=BPF_PROGRAM.replace("RINGBUF_PAGES", str(args.ring_pages)))

attached = False
for sym in ("__x64_sys_getpid", "sys_getpid"):
    if BPF.ksymname(sym) != 0xFFFFFFFFFFFFFFFF:
        b.attach_kprobe(event=sym, fn_name="probe_getpid")
        attached = True
        break

if not attached:
    print(
        json.dumps({"error": "Could not find a suitable getpid syscall symbol"}),
        flush=True,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Ring-buffer callback
# ---------------------------------------------------------------------------

def handle_event(ctx, data, size):
    """Called by BCC for every event committed to the ring buffer."""
    global done
    if done:
        return

    recv_time_ns = time.monotonic_ns()
    ev = ct.cast(data, ct.POINTER(Event)).contents
    latency_ns = recv_time_ns - ev.kernel_ts
    if latency_ns > 0:
        latencies_ns.append(latency_ns)

    if len(latencies_ns) >= TARGET_EVENTS:
        done = True

b["events"].open_ring_buffer(handle_event)

# ---------------------------------------------------------------------------
# Trigger loop
# ---------------------------------------------------------------------------

print("Collecting %d events via BPF_RINGBUF …" % TARGET_EVENTS, file=sys.stderr)

wall_start = time.monotonic()

try:
    while not done:
        os.getpid()
        # ring_buffer_poll() processes pending events from the ring buffer.
        b.ring_buffer_poll(timeout=0)
except KeyboardInterrupt:
    pass

wall_end = time.monotonic()
elapsed_sec = wall_end - wall_start

# ---------------------------------------------------------------------------
# Compute and emit metrics
# ---------------------------------------------------------------------------

stats = compute_stats(latencies_ns)
events_per_sec = stats["count"] / elapsed_sec if elapsed_sec > 0 else 0.0

result = {
    "benchmark":      "bench_ringbuf",
    "transport":      "BPF_RINGBUF",
    "count":          stats["count"],
    "mean_ns":        round(stats["mean"],  2),
    "p50_ns":         round(stats["p50"],   2),
    "p95_ns":         round(stats["p95"],   2),
    "p99_ns":         round(stats["p99"],   2),
    "stdev_ns":       round(stats["stdev"], 2),
    "min_ns":         round(stats["min"],   2),
    "max_ns":         round(stats["max"],   2),
    "events_per_sec": round(events_per_sec, 2),
    "elapsed_sec":    round(elapsed_sec,    4),
}

write_result("bench_ringbuf", result, output_dir=args.output_dir)
print(json.dumps(result))
