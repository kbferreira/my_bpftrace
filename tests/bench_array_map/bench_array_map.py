#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_array_map.py - Benchmark BPF_ARRAY poll-based counter read latency.
#
# Methodology:
#   A tracepoint on sched:sched_switch atomically increments a single counter
#   stored at index 0 of a BPF_ARRAY map.  Userspace reads array[0] every 1 ms,
#   computes the increment rate (events/sec) and the read round-trip latency.
#
#   BPF_ARRAY is simpler and faster than BPF_HASH for single fixed-size
#   counters because it uses a pre-allocated contiguous array and avoids
#   hash-table overhead.
#
# Metrics reported:
#   poll_count              - number of reads performed
#   total_increments        - final value of the counter after the run
#   mean_read_latency_us    - mean time for a single array[0] read (µs)
#   p99_read_latency_us     - 99th-percentile read latency (µs)
#   increment_rate_per_sec  - average counter increments per second
#
# Usage:
#   sudo python3 tests/bench_array_map/bench_array_map.py
#   sudo python3 tests/bench_array_map/bench_array_map.py --duration 5
#
# Output (stdout): single JSON object with benchmark metrics.

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from bench_utils import compute_stats, write_result, BenchmarkTimer

from bcc import BPF

# ---------------------------------------------------------------------------
# eBPF (C) kernel program
# ---------------------------------------------------------------------------

BPF_PROGRAM = r"""
#include <linux/sched.h>

// BPF_ARRAY with a single slot (index 0) used as a global event counter.
// BPF_ARRAY is backed by a contiguous memory region; lookup by index is O(1)
// and avoids the hash-table overhead of BPF_HASH.
BPF_ARRAY(counter_map, u64, 1);

TRACEPOINT_PROBE(sched, sched_switch) {
    int key = 0;

    // lock_xadd (atomic add) increments the counter safely across CPUs.
    // BCC's .increment() uses __sync_fetch_and_add for this purpose.
    counter_map.increment(key);
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Benchmark BPF_ARRAY counter read round-trip latency."
)
parser.add_argument(
    "--duration", "-d",
    type=float,
    default=5.0,
    help="Duration in seconds to poll the array (default: 5)",
)
parser.add_argument(
    "--interval-ms",
    type=float,
    default=1.0,
    help="Polling interval in milliseconds (default: 1)",
)
parser.add_argument(
    "--output-dir",
    default=os.path.join(os.path.dirname(__file__), "..", "results"),
    help="Directory for .jsonl result files",
)
args = parser.parse_args()

DURATION_SEC = args.duration
INTERVAL_SEC = args.interval_ms / 1000.0

# ---------------------------------------------------------------------------
# Load and attach BPF program
# ---------------------------------------------------------------------------

b = BPF(text=BPF_PROGRAM)
# TRACEPOINT_PROBE macro auto-attaches via the kernel tracepoint infrastructure.

print(
    "Polling BPF_ARRAY counter for %.1f s every %.1f ms …" % (DURATION_SEC, args.interval_ms),
    file=sys.stderr,
)

# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------

read_latencies_us = []   # time to read array[0], in microseconds
prev_value        = 0    # previous counter value for delta computation
wall_start        = time.monotonic()
deadline          = wall_start + DURATION_SEC

try:
    while time.monotonic() < deadline:
        with BenchmarkTimer() as t:
            # Read index 0 — a single bpf(BPF_MAP_LOOKUP_ELEM) syscall.
            val = b["counter_map"][0].value

        read_latencies_us.append(t.elapsed_ns / 1_000.0)

        elapsed = t.elapsed_ns / 1e9
        sleep_time = max(0.0, INTERVAL_SEC - elapsed)
        if sleep_time > 0:
            time.sleep(sleep_time)

except KeyboardInterrupt:
    pass

wall_end   = time.monotonic()
elapsed_sec = wall_end - wall_start

# ---------------------------------------------------------------------------
# Final read: get the absolute counter value
# ---------------------------------------------------------------------------

try:
    total_increments = b["counter_map"][0].value
except Exception:
    total_increments = 0

increment_rate = total_increments / elapsed_sec if elapsed_sec > 0 else 0.0

# ---------------------------------------------------------------------------
# Compute and emit metrics
# ---------------------------------------------------------------------------

stats = compute_stats(read_latencies_us)

result = {
    "benchmark":              "bench_array_map",
    "transport":              "BPF_ARRAY",
    "poll_count":             stats["count"],
    "total_increments":       total_increments,
    "mean_read_latency_us":   round(stats["mean"],  3),
    "p50_read_latency_us":    round(stats["p50"],   3),
    "p95_read_latency_us":    round(stats["p95"],   3),
    "p99_read_latency_us":    round(stats["p99"],   3),
    "stdev_read_latency_us":  round(stats["stdev"], 3),
    "min_read_latency_us":    round(stats["min"],   3),
    "max_read_latency_us":    round(stats["max"],   3),
    "increment_rate_per_sec": round(increment_rate, 2),
    "elapsed_sec":            round(elapsed_sec,    4),
}

write_result("bench_array_map", result, output_dir=args.output_dir)
print(json.dumps(result))
