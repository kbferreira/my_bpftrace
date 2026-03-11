#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_perf_output.py - Benchmark BPF_PERF_OUTPUT (perf ring buffer) latency.
#
# Methodology:
#   A kprobe is attached to the __x64_sys_getpid (or sys_getpid) syscall.
#   A tight userspace loop calls os.getpid() to trigger the probe at high
#   frequency.  Each kernel invocation records a timestamp with bpf_ktime_get_ns()
#   and submits a fixed-size struct via perf_submit().  The userspace callback
#   records its own monotonic timestamp on receipt and computes the end-to-end
#   delivery latency.
#
# Usage:
#   sudo python3 tests/bench_perf_output/bench_perf_output.py
#   sudo python3 tests/bench_perf_output/bench_perf_output.py --events 10000
#
# Output (stdout):  single JSON object with benchmark metrics.

import argparse
import json
import os
import sys
import time
import ctypes as ct

# Allow running as: sudo python3 tests/bench_perf_output/bench_perf_output.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from bench_utils import compute_stats, write_result, BenchmarkTimer

from bcc import BPF

# ---------------------------------------------------------------------------
# eBPF (C) kernel program
# ---------------------------------------------------------------------------

BPF_PROGRAM = r"""
#include <linux/sched.h>

// Fixed-size event struct submitted through the perf ring buffer.
// kernel_ts: bpf_ktime_get_ns() timestamp recorded in the probe —
//            used to compute end-to-end kernel→userspace latency.
struct event_t {
    u64 kernel_ts;   // nanoseconds since boot (bpf_ktime_get_ns)
    u32 pid;
};

// BPF_PERF_OUTPUT declares a special map backed by the perf subsystem.
// perf_submit() copies the event into a per-CPU ring buffer; the BCC
// open_perf_buffer() / perf_buffer_poll() API delivers it to userspace.
BPF_PERF_OUTPUT(events);

// Probe fires on every call to sys_getpid (triggered by the userspace loop).
int probe_getpid(struct pt_regs *ctx) {
    struct event_t ev = {};

    // bpf_ktime_get_ns() returns nanoseconds since system boot — monotonic,
    // consistent across CPUs, and available in all BPF program types.
    ev.kernel_ts = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // perf_submit() enqueues ev into the per-CPU perf ring buffer.
    // ctx is the probe context required by the BCC helper.
    events.perf_submit(ctx, &ev, sizeof(ev));
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
    description="Benchmark BPF_PERF_OUTPUT kernel→userspace event latency."
)
parser.add_argument(
    "--events", "-n",
    type=int,
    default=10_000,
    help="Number of events to collect before reporting (default: 10000)",
)
parser.add_argument(
    "--page-cnt",
    type=int,
    default=64,
    help=(
        "Per-CPU perf ring-buffer size in pages (must be a power of 2, default: 64). "
        "Larger values reduce back-pressure and lower P99 latency at the cost of memory."
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
# State shared between the perf callback and the main loop
# ---------------------------------------------------------------------------

latencies_ns = []   # per-event kernel→userspace latency in nanoseconds
done = False        # set to True once TARGET_EVENTS samples are collected

# ---------------------------------------------------------------------------
# Load and attach BPF program
# ---------------------------------------------------------------------------

b = BPF(text=BPF_PROGRAM)

# Try common syscall entry-point names across kernel versions / architectures.
# On x86-64 kernels with CONFIG_KALLSYMS, sys_getpid is typically wrapped as
# __x64_sys_getpid; on older kernels it may appear as sys_getpid.
attached = False
for sym in ("__x64_sys_getpid", "sys_getpid"):
    if BPF.ksymname(sym) != 0xFFFFFFFFFFFFFFFF:
        b.attach_kprobe(event=sym, fn_name="probe_getpid")
        attached = True
        break

if not attached:
    print(
        json.dumps({"error": "Could not find a suitable getpid syscall symbol to attach"}),
        flush=True,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Perf-buffer callback
# ---------------------------------------------------------------------------

def handle_event(cpu, data, size):
    """Called by BCC for every event delivered from the kernel ring buffer."""
    global done
    if done:
        return

    # recv_time_ns is measured as soon as we enter the Python callback —
    # it represents the moment the event became visible in userspace.
    recv_time_ns = time.monotonic_ns()

    ev = ct.cast(data, ct.POINTER(Event)).contents
    latency_ns = recv_time_ns - ev.kernel_ts
    # Discard obviously invalid latencies (e.g. clock skew at startup).
    if latency_ns > 0:
        latencies_ns.append(latency_ns)

    if len(latencies_ns) >= TARGET_EVENTS:
        done = True

# Open the perf ring buffer with a callback; page_cnt must be a power of 2.
# Larger page_cnt reduces back-pressure at the cost of memory (page_cnt × 4 KiB per CPU).
b["events"].open_perf_buffer(handle_event, page_cnt=args.page_cnt)

# ---------------------------------------------------------------------------
# Trigger loop: call os.getpid() at high frequency to generate events
# ---------------------------------------------------------------------------

print("Collecting %d events via BPF_PERF_OUTPUT …" % TARGET_EVENTS, file=sys.stderr)

wall_start = time.monotonic()

try:
    while not done:
        # Drive events: syscall → kprobe fires → perf_submit → callback
        os.getpid()
        # Poll delivers pending events from the ring buffer to the callback.
        b.perf_buffer_poll(timeout=0)
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
    "benchmark":      "bench_perf_output",
    "transport":      "BPF_PERF_OUTPUT",
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

# Persist to .jsonl for historical comparison
write_result("bench_perf_output", result, output_dir=args.output_dir)

# Emit single JSON object to stdout for run_all.py to parse
print(json.dumps(result))
