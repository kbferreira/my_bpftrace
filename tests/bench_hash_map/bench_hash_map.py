#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_hash_map.py - Benchmark BPF_HASH poll-based read-back overhead.
#
# Methodology:
#   A tracepoint on sched:sched_switch accumulates per-PID event counts in a
#   BPF_HASH map (matching the style in hello.sched_switch.py and offcpu_time.py).
#   Userspace polls the entire map every 1 ms for a configurable duration and
#   measures the round-trip read latency of iterating all entries.
#
# Metrics reported:
#   poll_count           - number of map polls performed
#   total_events_read    - sum of all per-PID counters after the run
#   mean_read_latency_us - mean wall-clock time to iterate the full map (µs)
#   p99_read_latency_us  - 99th-percentile map-read latency (µs)
#   map_entries          - number of distinct PIDs seen in the map
#
# Usage:
#   sudo python3 tests/bench_hash_map/bench_hash_map.py
#   sudo python3 tests/bench_hash_map/bench_hash_map.py --duration 5
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

// BPF_HASH maps a u32 PID to a u64 event count.
// Each sched_switch event increments the count for the outgoing PID.
// The poll-based userspace reader iterates this map at fixed intervals.
BPF_HASH(pid_count, u32, u64);

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 pid = args->prev_pid;

    // Lookup the current counter for this PID.
    // bpf_map_lookup_elem is the underlying helper; BCC wraps it as .lookup().
    u64 *val = pid_count.lookup(&pid);
    if (val) {
        // Atomically increment the existing counter via lock_xadd.
        // BCC's .increment() wraps __sync_fetch_and_add.
        pid_count.increment(pid);
    } else {
        // First time we see this PID: initialise counter to 1.
        u64 one = 1;
        pid_count.update(&pid, &one);
    }
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Benchmark BPF_HASH poll-based map read-back overhead."
)
parser.add_argument(
    "--duration", "-d",
    type=float,
    default=5.0,
    help="Duration in seconds to poll the map (default: 5)",
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

DURATION_SEC   = args.duration
INTERVAL_SEC   = args.interval_ms / 1000.0

# ---------------------------------------------------------------------------
# Load and attach BPF program
# ---------------------------------------------------------------------------

b = BPF(text=BPF_PROGRAM)
# TRACEPOINT_PROBE macro auto-attaches; no explicit attach_tracepoint() needed.

print(
    "Polling BPF_HASH map for %.1f s every %.1f ms …" % (DURATION_SEC, args.interval_ms),
    file=sys.stderr,
)

# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------

read_latencies_us = []   # time to iterate the full map, in microseconds
deadline = time.monotonic() + DURATION_SEC

try:
    while time.monotonic() < deadline:
        with BenchmarkTimer() as t:
            # Iterate over all map entries — this is the operation we time.
            # BCC returns a ctypes-wrapped iterable; each item is a (key, value) pair.
            total = sum(v.value for v in b["pid_count"].values())

        read_latencies_us.append(t.elapsed_ns / 1_000.0)

        # Sleep for the remainder of the interval, clamping to ≥ 0.
        elapsed = t.elapsed_ns / 1e9
        sleep_time = max(0.0, INTERVAL_SEC - elapsed)
        if sleep_time > 0:
            time.sleep(sleep_time)

except KeyboardInterrupt:
    pass

# ---------------------------------------------------------------------------
# Final map read: collect totals
# ---------------------------------------------------------------------------

pid_map = b["pid_count"]
final_counts = {k.value: v.value for k, v in pid_map.items()}
total_events = sum(final_counts.values())
map_entries  = len(final_counts)

# ---------------------------------------------------------------------------
# Compute and emit metrics
# ---------------------------------------------------------------------------

stats = compute_stats(read_latencies_us)

result = {
    "benchmark":             "bench_hash_map",
    "transport":             "BPF_HASH",
    "poll_count":            stats["count"],
    "total_events_read":     total_events,
    "map_entries":           map_entries,
    "mean_read_latency_us":  round(stats["mean"],  3),
    "p50_read_latency_us":   round(stats["p50"],   3),
    "p95_read_latency_us":   round(stats["p95"],   3),
    "p99_read_latency_us":   round(stats["p99"],   3),
    "stdev_read_latency_us": round(stats["stdev"], 3),
    "min_read_latency_us":   round(stats["min"],   3),
    "max_read_latency_us":   round(stats["max"],   3),
    "duration_sec":          round(DURATION_SEC,   2),
}

write_result("bench_hash_map", result, output_dir=args.output_dir)
print(json.dumps(result))
