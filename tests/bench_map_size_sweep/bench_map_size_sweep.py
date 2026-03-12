#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_map_size_sweep.py - Measure map read latency vs. entry count for BPF_HASH and BPF_ARRAY.
#
# Methodology:
#   For each (transport, entry_count) combination:
#     1. A BPF map is created with a maximum size >= entry_count.
#     2. The map is pre-populated from userspace with entry_count entries
#        (BCC map.update() for each key).
#     3. A full map iteration is timed 100 times (configurable via --iterations).
#        - BPF_HASH: iterates all (key, value) pairs via b["map"].items().
#        - BPF_ARRAY: iterates all N entries via b["map"].items().
#     4. Per-iteration latency (µs) and total bytes transferred per iteration
#        are recorded.
#
#   No kernel-side eBPF program is needed: the BPF maps are created via BCC and
#   read entirely from userspace — this isolates the userspace map-read cost.
#
# Usage:
#   sudo python3 tests/bench_map_size_sweep/bench_map_size_sweep.py
#   sudo python3 tests/bench_map_size_sweep/bench_map_size_sweep.py --iterations 200
#   sudo python3 tests/bench_map_size_sweep/bench_map_size_sweep.py \
#       --sizes 100,1000,10000 --output-dir /tmp/results
#
# Output (stdout): single JSON object with transport_results schema.

import argparse
import ctypes as ct
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from bench_utils import compute_stats, write_result, BenchmarkTimer

# ---------------------------------------------------------------------------
# eBPF (C) programs — minimal stubs that only define the maps.
# ---------------------------------------------------------------------------

# BPF_HASH program: map key is u64, value is u64.
# MAX_ENTRIES is substituted at load time for the current sweep point.
_BPF_HASH_PROG = r"""
BPF_HASH(bench_map, u64, u64, MAX_ENTRIES);
"""

# BPF_ARRAY program: key is u32 index, value is u64.
_BPF_ARRAY_PROG = r"""
BPF_ARRAY(bench_map, u64, MAX_ENTRIES);
"""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

DEFAULT_SIZES = [100, 500, 1000, 5000, 10000, 50000, 100000]

parser = argparse.ArgumentParser(
    description="Sweep map entry counts for BPF_HASH and BPF_ARRAY read latency.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument(
    "--iterations", "-n",
    type=int,
    default=100,
    help="Number of full map iterations to time per (transport, entry_count) point",
)
parser.add_argument(
    "--sizes",
    type=str,
    default=",".join(str(s) for s in DEFAULT_SIZES),
    help="Comma-separated list of map entry counts to sweep",
)
parser.add_argument(
    "--output-dir",
    default=os.path.join(os.path.dirname(__file__), "..", "results"),
    help="Directory for .jsonl result files",
)
args = parser.parse_args()

NUM_ITERATIONS = args.iterations
try:
    SIZES = [int(s.strip()) for s in args.sizes.split(",") if s.strip()]
except ValueError as exc:
    print("ERROR: --sizes must be a comma-separated list of integers: %s" % exc,
          file=sys.stderr)
    sys.exit(1)

# Value size: u64 = 8 bytes.
VALUE_SIZE_BYTES = 8

# ---------------------------------------------------------------------------
# Benchmark runners
# ---------------------------------------------------------------------------

def _run_hash_map(entry_count, num_iterations):
    """
    Create a BPF_HASH with entry_count entries, time num_iterations full reads.
    Returns a result dict.
    """
    from bcc import BPF

    # Substitute MAX_ENTRIES at string level so BCC allocates the right map size.
    prog = _BPF_HASH_PROG.replace("MAX_ENTRIES", str(entry_count))
    b = BPF(text=prog)

    bench_map = b["bench_map"]

    # Pre-populate the map from userspace using sequential u64 keys.
    # Each value is the key itself (arbitrary; we just need valid entries).
    print(
        "  BPF_HASH  entries=%7d  populating …" % entry_count,
        file=sys.stderr,
        end="",
        flush=True,
    )
    key_t = ct.c_uint64
    val_t = ct.c_uint64
    for i in range(entry_count):
        bench_map[key_t(i)] = val_t(i)
    print("  timing %d iterations …" % num_iterations, file=sys.stderr, end="", flush=True)

    iter_latencies_us = []
    for _ in range(num_iterations):
        with BenchmarkTimer() as t:
            # Full map iteration: one bpf_map_get_next_key + bpf_map_lookup_elem per entry.
            _sum = sum(v.value for _, v in bench_map.items())
        iter_latencies_us.append(t.elapsed_ns / 1_000.0)

    print("  done", file=sys.stderr)

    stats = compute_stats(iter_latencies_us)
    # Total bytes transferred per full iteration: key (8B) + value (8B) × entry_count.
    total_bytes_per_iter = entry_count * (8 + VALUE_SIZE_BYTES)
    mean_iter_us = stats["mean"]
    bytes_per_us = (total_bytes_per_iter / mean_iter_us) if mean_iter_us > 0 else 0.0

    return {
        "map_entries":          entry_count,
        "iterations":           num_iterations,
        "mean_iter_us":         round(stats["mean"],  3),
        "p50_iter_us":          round(stats["p50"],   3),
        "p95_iter_us":          round(stats["p95"],   3),
        "p99_iter_us":          round(stats["p99"],   3),
        "stdev_iter_us":        round(stats["stdev"], 3),
        "min_iter_us":          round(stats["min"],   3),
        "max_iter_us":          round(stats["max"],   3),
        "total_bytes_per_iter": total_bytes_per_iter,
        "bytes_per_us":         round(bytes_per_us,   3),
    }


def _run_array_map(entry_count, num_iterations):
    """
    Create a BPF_ARRAY with entry_count entries, time num_iterations full reads.
    Returns a result dict.
    """
    from bcc import BPF

    prog = _BPF_ARRAY_PROG.replace("MAX_ENTRIES", str(entry_count))
    b = BPF(text=prog)

    bench_map = b["bench_map"]

    # Pre-populate the array from userspace.
    print(
        "  BPF_ARRAY entries=%7d  populating …" % entry_count,
        file=sys.stderr,
        end="",
        flush=True,
    )
    key_t = ct.c_uint32
    val_t = ct.c_uint64
    for i in range(entry_count):
        bench_map[key_t(i)] = val_t(i)
    print("  timing %d iterations …" % num_iterations, file=sys.stderr, end="", flush=True)

    iter_latencies_us = []
    for _ in range(num_iterations):
        with BenchmarkTimer() as t:
            # Full array iteration: one bpf_map_lookup_elem per slot.
            _sum = sum(v.value for _, v in bench_map.items())
        iter_latencies_us.append(t.elapsed_ns / 1_000.0)

    print("  done", file=sys.stderr)

    stats = compute_stats(iter_latencies_us)
    # BPF_ARRAY value size is VALUE_SIZE_BYTES; key is u32 = 4 bytes.
    total_bytes_per_iter = entry_count * (4 + VALUE_SIZE_BYTES)
    mean_iter_us = stats["mean"]
    bytes_per_us = (total_bytes_per_iter / mean_iter_us) if mean_iter_us > 0 else 0.0

    return {
        "map_entries":          entry_count,
        "iterations":           num_iterations,
        "mean_iter_us":         round(stats["mean"],  3),
        "p50_iter_us":          round(stats["p50"],   3),
        "p95_iter_us":          round(stats["p95"],   3),
        "p99_iter_us":          round(stats["p99"],   3),
        "stdev_iter_us":        round(stats["stdev"], 3),
        "min_iter_us":          round(stats["min"],   3),
        "max_iter_us":          round(stats["max"],   3),
        "total_bytes_per_iter": total_bytes_per_iter,
        "bytes_per_us":         round(bytes_per_us,   3),
    }

# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------

print(
    "bench_map_size_sweep: sizes=%s  iterations=%d" % (SIZES, NUM_ITERATIONS),
    file=sys.stderr,
)

try:
    from bcc import BPF as _BPF_CHECK  # noqa: F401
except ImportError:
    print(json.dumps({"error": "BCC not available — install python3-bpfcc"}))
    sys.exit(1)

transport_results = {
    "BPF_HASH":  [],
    "BPF_ARRAY": [],
}

try:
    for entry_count in SIZES:
        # --- BPF_HASH ---
        try:
            point = _run_hash_map(entry_count, NUM_ITERATIONS)
            transport_results["BPF_HASH"].append(point)
            print(
                "    → mean=%.1f µs  p99=%.1f µs  bytes_per_us=%.2f" % (
                    point["mean_iter_us"], point["p99_iter_us"], point["bytes_per_us"]
                ),
                file=sys.stderr,
            )
        except Exception as exc:
            print("    BPF_HASH ERROR: %s" % exc, file=sys.stderr)
            transport_results["BPF_HASH"].append(
                {"map_entries": entry_count, "error": str(exc)}
            )

        # --- BPF_ARRAY ---
        try:
            point = _run_array_map(entry_count, NUM_ITERATIONS)
            transport_results["BPF_ARRAY"].append(point)
            print(
                "    → mean=%.1f µs  p99=%.1f µs  bytes_per_us=%.2f" % (
                    point["mean_iter_us"], point["p99_iter_us"], point["bytes_per_us"]
                ),
                file=sys.stderr,
            )
        except Exception as exc:
            print("    BPF_ARRAY ERROR: %s" % exc, file=sys.stderr)
            transport_results["BPF_ARRAY"].append(
                {"map_entries": entry_count, "error": str(exc)}
            )

except KeyboardInterrupt:
    print("\nInterrupted — emitting partial results.", file=sys.stderr)

# ---------------------------------------------------------------------------
# Emit result
# ---------------------------------------------------------------------------

result = {
    "benchmark":         "bench_map_size_sweep",
    "transport_results": transport_results,
}

write_result("bench_map_size_sweep", result, output_dir=args.output_dir)
print(json.dumps(result))
