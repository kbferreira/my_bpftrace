#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_utils.py - Shared utilities for the eBPF kernel-to-userspace benchmark suite.
#
# Provides:
#   - compute_stats(samples)  : mean/p50/p95/p99/stdev/min/max
#   - write_result(...)       : append a JSON line to results/<name>.jsonl
#   - BenchmarkTimer          : context manager for wall-clock nanosecond timing
#
# No BPF dependency — can be unit-tested independently.

import json
import math
import os
import time


def compute_stats(samples: list) -> dict:
    """
    Compute descriptive statistics for a list of numeric samples.

    Returns a dict with keys:
        count   - number of samples
        mean    - arithmetic mean
        p50     - 50th percentile (median)
        p95     - 95th percentile
        p99     - 99th percentile
        stdev   - population standard deviation
        min     - minimum value
        max     - maximum value
    """
    if not samples:
        return {
            "count": 0,
            "mean": 0.0,
            "p50": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "stdev": 0.0,
            "min": 0.0,
            "max": 0.0,
        }

    n = len(samples)
    sorted_samples = sorted(samples)

    mean = sum(sorted_samples) / n

    # Percentile using nearest-rank method
    def percentile(sorted_data, pct):
        index = int(math.ceil(pct / 100.0 * len(sorted_data))) - 1
        index = max(0, min(index, len(sorted_data) - 1))
        return sorted_data[index]

    variance = sum((x - mean) ** 2 for x in sorted_samples) / n

    return {
        "count": n,
        "mean": mean,
        "p50": percentile(sorted_samples, 50),
        "p95": percentile(sorted_samples, 95),
        "p99": percentile(sorted_samples, 99),
        "stdev": math.sqrt(variance),
        "min": sorted_samples[0],
        "max": sorted_samples[-1],
    }


def write_result(benchmark_name: str, metrics: dict, output_dir: str = "results/") -> None:
    """
    Append a JSON-lines record to results/<benchmark_name>.jsonl.

    Each record includes a UTC timestamp alongside the supplied metrics dict.
    The output_dir is created if it does not already exist.
    """
    os.makedirs(output_dir, exist_ok=True)
    record = {
        "benchmark": benchmark_name,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metrics": metrics,
    }
    path = os.path.join(output_dir, "%s.jsonl" % benchmark_name)
    with open(path, "a") as fh:
        fh.write(json.dumps(record) + "\n")


class BenchmarkTimer:
    """
    Context manager that records wall-clock duration in nanoseconds.

    Usage:
        with BenchmarkTimer() as t:
            do_work()
        print(t.elapsed_ns)
    """

    def __init__(self):
        self.start_ns = None
        self.end_ns = None
        self.elapsed_ns = None

    def __enter__(self):
        self.start_ns = time.monotonic_ns()
        return self

    def __exit__(self, *_):
        self.end_ns = time.monotonic_ns()
        self.elapsed_ns = self.end_ns - self.start_ns
