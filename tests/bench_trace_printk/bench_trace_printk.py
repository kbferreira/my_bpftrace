#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_trace_printk.py - Benchmark bpf_trace_printk throughput and latency.
#
# Methodology:
#   A tracepoint on sched:sched_switch calls bpf_trace_printk() for every
#   event, embedding a bpf_ktime_get_ns() timestamp in the message.
#   A background thread reads /sys/kernel/debug/tracing/trace_pipe line by
#   line, parses the kernel timestamp, and computes the end-to-end pipe-read
#   latency (time from printk to line receipt in userspace).
#
#   bpf_trace_printk is the simplest (and worst-case) transport: it is
#   throttled by the kernel to ~1 message per 5 µs and shares the global
#   trace_pipe with all other BPF programs on the system.
#
# Metrics reported:
#   lines_received       - number of trace_pipe lines captured
#   mean_pipe_latency_ns - mean kernel→userspace delivery latency (ns)
#   p99_pipe_latency_ns  - 99th-percentile pipe latency (ns)
#   lines_per_sec        - trace_pipe read throughput
#
# Usage:
#   sudo python3 tests/bench_trace_printk/bench_trace_printk.py
#   sudo python3 tests/bench_trace_printk/bench_trace_printk.py --duration 5
#
# Output (stdout): single JSON object with benchmark metrics.

import argparse
import json
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from bench_utils import compute_stats, write_result

from bcc import BPF

# ---------------------------------------------------------------------------
# eBPF (C) kernel program
# ---------------------------------------------------------------------------

BPF_PROGRAM = r"""
#include <linux/sched.h>

TRACEPOINT_PROBE(sched, sched_switch) {
    // bpf_ktime_get_ns() returns nanoseconds since boot — embedded in the
    // trace message so userspace can compute delivery latency.
    u64 ts = bpf_ktime_get_ns();

    // bpf_trace_printk writes to /sys/kernel/debug/tracing/trace_pipe.
    // It is throttled by the kernel (~1 msg per 5 µs per CPU) and is
    // intended as a debugging aid, not a high-performance transport.
    // The format string is limited to 3 format specifiers in older kernels.
    bpf_trace_printk("bpf_bench ts=%llu\\n", ts);
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Benchmark bpf_trace_printk pipe throughput and latency."
)
parser.add_argument(
    "--duration", "-d",
    type=float,
    default=5.0,
    help="Duration in seconds to collect trace_pipe output (default: 5)",
)
parser.add_argument(
    "--output-dir",
    default=os.path.join(os.path.dirname(__file__), "..", "results"),
    help="Directory for .jsonl result files",
)
args = parser.parse_args()

DURATION_SEC = args.duration
TRACE_PIPE   = "/sys/kernel/debug/tracing/trace_pipe"

# ---------------------------------------------------------------------------
# Load and attach BPF program
# ---------------------------------------------------------------------------

b = BPF(text=BPF_PROGRAM)
# TRACEPOINT_PROBE macro auto-attaches to sched:sched_switch.

# ---------------------------------------------------------------------------
# Background thread: read trace_pipe and parse timestamps
# ---------------------------------------------------------------------------

# Pattern: "bpf_bench ts=<kernel_ns>"
TS_PATTERN = re.compile(r"bpf_bench ts=(\d+)")

pipe_latencies_ns = []   # kernel→userspace delivery latency in nanoseconds
stop_event        = threading.Event()
lines_received    = [0]  # use list for mutation from thread


def read_trace_pipe():
    """Background thread: drain trace_pipe and parse embedded timestamps."""
    try:
        with open(TRACE_PIPE, "r", buffering=1) as pipe:
            while not stop_event.is_set():
                line = pipe.readline()
                if not line:
                    time.sleep(0.0001)
                    continue

                recv_ns = time.monotonic_ns()
                lines_received[0] += 1

                m = TS_PATTERN.search(line)
                if m:
                    kernel_ns = int(m.group(1))
                    latency   = recv_ns - kernel_ns
                    # Discard obviously invalid samples (clock skew or stale pipe
                    # data left over from a previous run).  10 seconds is a generous
                    # upper bound: any real delivery latency larger than this indicates
                    # a measurement artifact, not genuine pipe latency.
                    MAX_VALID_LATENCY_NS = 10_000_000_000  # 10 seconds in nanoseconds
                    if 0 < latency < MAX_VALID_LATENCY_NS:
                        pipe_latencies_ns.append(latency)

    except (OSError, PermissionError) as exc:
        print("Warning: could not read %s: %s" % (TRACE_PIPE, exc), file=sys.stderr)


reader = threading.Thread(target=read_trace_pipe, daemon=True)
reader.start()

print(
    "Capturing bpf_trace_printk output for %.1f s …" % DURATION_SEC,
    file=sys.stderr,
)

# ---------------------------------------------------------------------------
# Run for the configured duration
# ---------------------------------------------------------------------------

wall_start = time.monotonic()
try:
    time.sleep(DURATION_SEC)
except KeyboardInterrupt:
    pass

wall_end = time.monotonic()
elapsed_sec = wall_end - wall_start

# Signal reader thread to stop and wait briefly for it to flush.
stop_event.set()
reader.join(timeout=2.0)

# ---------------------------------------------------------------------------
# Compute and emit metrics
# ---------------------------------------------------------------------------

stats = compute_stats(pipe_latencies_ns)
lines_per_sec = lines_received[0] / elapsed_sec if elapsed_sec > 0 else 0.0

result = {
    "benchmark":           "bench_trace_printk",
    "transport":           "bpf_trace_printk",
    "lines_received":      lines_received[0],
    "lines_per_sec":       round(lines_per_sec,          2),
    "mean_pipe_latency_ns": round(stats["mean"],          2),
    "p50_pipe_latency_ns":  round(stats["p50"],           2),
    "p95_pipe_latency_ns":  round(stats["p95"],           2),
    "p99_pipe_latency_ns":  round(stats["p99"],           2),
    "stdev_pipe_latency_ns": round(stats["stdev"],        2),
    "min_pipe_latency_ns":  round(stats["min"],           2),
    "max_pipe_latency_ns":  round(stats["max"],           2),
    "latency_samples":      stats["count"],
    "elapsed_sec":          round(elapsed_sec,            4),
}

write_result("bench_trace_printk", result, output_dir=args.output_dir)
print(json.dumps(result))
