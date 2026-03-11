#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# run_all.py - Orchestrator for the eBPF kernel-to-userspace benchmark suite.
#
# Runs each benchmark as a subprocess, collects JSON results from stdout,
# prints a Markdown summary table, and saves a combined JSON file.
#
# Usage:
#   sudo python3 tests/run_all.py
#   sudo python3 tests/run_all.py --duration 10 --output-dir /tmp/bench_results
#
# Requirements:
#   - Must be run as root (eBPF programs require elevated privileges)
#   - BCC installed (https://github.com/iovisor/bcc/blob/master/INSTALL.md)
#   - Linux kernel >= 4.9 (>= 5.8 for bench_ringbuf)

import argparse
import json
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Benchmark registry — (name, script_path, transport_label)
# ---------------------------------------------------------------------------

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

BENCHMARKS = [
    {
        "name":      "bench_perf_output",
        "script":    os.path.join(TESTS_DIR, "bench_perf_output", "bench_perf_output.py"),
        "transport": "BPF_PERF_OUTPUT",
    },
    {
        "name":      "bench_ringbuf",
        "script":    os.path.join(TESTS_DIR, "bench_ringbuf", "bench_ringbuf.py"),
        "transport": "BPF_RINGBUF",
    },
    {
        "name":      "bench_hash_map",
        "script":    os.path.join(TESTS_DIR, "bench_hash_map", "bench_hash_map.py"),
        "transport": "BPF_HASH",
    },
    {
        "name":      "bench_array_map",
        "script":    os.path.join(TESTS_DIR, "bench_array_map", "bench_array_map.py"),
        "transport": "BPF_ARRAY",
    },
    {
        "name":      "bench_trace_printk",
        "script":    os.path.join(TESTS_DIR, "bench_trace_printk", "bench_trace_printk.py"),
        "transport": "bpf_trace_printk",
    },
]

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Run the full eBPF kernel→userspace benchmark suite.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument(
    "--duration", "-d",
    type=int,
    default=5,
    help="Duration in seconds per benchmark",
)
parser.add_argument(
    "--output-dir",
    default=os.path.join(TESTS_DIR, "results"),
    help="Directory for result files",
)
parser.add_argument(
    "--events", "-n",
    type=int,
    default=10_000,
    help="Target event count for latency benchmarks (perf_output, ringbuf)",
)
args = parser.parse_args()

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

if os.geteuid() != 0:
    print(
        "WARNING: Not running as root. eBPF programs require elevated privileges.\n"
        "         Re-run with: sudo python3 %s" % sys.argv[0],
        file=sys.stderr,
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_latency(result: dict) -> str:
    """Extract a human-readable mean latency string from a result dict."""
    if result.get("skipped"):
        return "skipped"
    # Latency benchmarks report in ns; poll benchmarks report in µs.
    if "mean_ns" in result:
        return "%.0f ns" % result["mean_ns"]
    if "mean_pipe_latency_ns" in result:
        return "%.0f ns" % result["mean_pipe_latency_ns"]
    if "mean_read_latency_us" in result:
        return "%.2f µs" % result["mean_read_latency_us"]
    return "—"


def _fmt_p99(result: dict) -> str:
    """Extract a human-readable P99 latency string from a result dict."""
    if result.get("skipped"):
        return "skipped"
    if "p99_ns" in result:
        return "%.0f ns" % result["p99_ns"]
    if "p99_pipe_latency_ns" in result:
        return "%.0f ns" % result["p99_pipe_latency_ns"]
    if "p99_read_latency_us" in result:
        return "%.2f µs" % result["p99_read_latency_us"]
    return "—"


def _fmt_throughput(result: dict) -> str:
    """Extract a human-readable throughput string from a result dict."""
    if result.get("skipped"):
        return "skipped"
    if "events_per_sec" in result:
        return "%.0f ev/s" % result["events_per_sec"]
    if "lines_per_sec" in result:
        return "%.0f lines/s" % result["lines_per_sec"]
    if "increment_rate_per_sec" in result:
        return "%.0f ev/s" % result["increment_rate_per_sec"]
    return "—"


def run_benchmark(bench: dict, duration: int, events: int, output_dir: str) -> dict:
    """
    Run a single benchmark script as a subprocess and return its parsed JSON result.
    Progress/diagnostic output (stderr) is forwarded to our own stderr.
    """
    cmd = [
        sys.executable,
        bench["script"],
        "--duration", str(duration),
        "--output-dir", output_dir,
    ]
    # Latency benchmarks accept --events; others ignore it.
    if bench["name"] in ("bench_perf_output", "bench_ringbuf"):
        cmd += ["--events", str(events)]

    print("\n[%s] Running: %s" % (bench["name"], " ".join(cmd)), file=sys.stderr)
    start = time.monotonic()

    # Allow up to 4× the configured duration for the benchmark to produce output,
    # plus a 60-second fixed buffer for BPF compilation and program load time.
    TIMEOUT_MULTIPLIER  = 4
    TIMEOUT_BUFFER_SEC  = 60
    timeout_sec = duration * TIMEOUT_MULTIPLIER + TIMEOUT_BUFFER_SEC

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=None,       # forward stderr directly to terminal
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        print("[%s] TIMED OUT" % bench["name"], file=sys.stderr)
        return {"benchmark": bench["name"], "error": "timeout"}
    except Exception as exc:
        print("[%s] ERROR: %s" % (bench["name"], exc), file=sys.stderr)
        return {"benchmark": bench["name"], "error": str(exc)}

    elapsed = time.monotonic() - start
    print("[%s] Finished in %.1f s (exit=%d)" % (bench["name"], elapsed, proc.returncode),
          file=sys.stderr)

    stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    if not stdout:
        return {"benchmark": bench["name"], "error": "no output"}

    # The last non-empty line should be the JSON result.
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError as exc:
                return {"benchmark": bench["name"], "error": "bad JSON: %s" % exc}

    return {"benchmark": bench["name"], "error": "JSON not found in output", "raw": stdout}

# ---------------------------------------------------------------------------
# Main: run all benchmarks
# ---------------------------------------------------------------------------

os.makedirs(args.output_dir, exist_ok=True)

print("=" * 70, file=sys.stderr)
print("eBPF Kernel→Userspace Overhead Benchmark Suite", file=sys.stderr)
print("Duration per benchmark: %d s | Target events: %d" % (args.duration, args.events),
      file=sys.stderr)
print("=" * 70, file=sys.stderr)

all_results = []
for bench in BENCHMARKS:
    result = run_benchmark(bench, args.duration, args.events, args.output_dir)
    result["_transport"] = bench["transport"]
    all_results.append(result)

# ---------------------------------------------------------------------------
# Save combined JSON summary
# ---------------------------------------------------------------------------

timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
summary_path = os.path.join(args.output_dir, "summary_%s.json" % timestamp)
with open(summary_path, "w") as fh:
    json.dump(
        {
            "suite_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_per_bench_sec": args.duration,
            "target_events": args.events,
            "results": all_results,
        },
        fh,
        indent=2,
    )
print("\nFull results saved to: %s" % summary_path, file=sys.stderr)

# ---------------------------------------------------------------------------
# Print Markdown summary table
# ---------------------------------------------------------------------------

COL_W = [20, 18, 18, 18, 22]
HEADERS = ["Benchmark", "Transport", "Mean Latency", "P99 Latency", "Throughput (events/s)"]

def _row(cells):
    return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, COL_W)) + " |"

separator = "| " + " | ".join("-" * w for w in COL_W) + " |"

print()
print(_row(HEADERS))
print(separator)
for result in all_results:
    name      = result.get("benchmark", "?")
    transport = result.get("_transport", result.get("transport", "?"))
    if result.get("error"):
        print(_row([name, transport, "ERROR", result["error"][:16], "—"]))
    else:
        print(_row([
            name,
            transport,
            _fmt_latency(result),
            _fmt_p99(result),
            _fmt_throughput(result),
        ]))

print()
print("Results directory: %s" % args.output_dir)
