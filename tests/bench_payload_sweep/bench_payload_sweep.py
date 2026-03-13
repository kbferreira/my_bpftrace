#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_payload_sweep.py - Sweep event payload sizes for BPF_PERF_OUTPUT and BPF_RINGBUF.
#
# Methodology:
#   For each (transport, payload_size) combination the eBPF program is re-compiled
#   with -DPAYLOAD_SIZE=N so that the kernel-side struct carries a byte array of
#   exactly N bytes.  A kprobe on sys_getpid fires on every os.getpid() call,
#   records bpf_ktime_get_ns(), fills the payload with 0xAB, and submits the event.
#   Userspace measures end-to-end latency as in bench_perf_output.py.
#
#   BPF_RINGBUF points are skipped on kernels < 5.8.
#
# Usage:
#   sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py
#   sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py --events 5000
#   sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py \
#       --sizes 8,64,512,4096 --output-dir /tmp/results
#
# Output (stdout): single JSON object with transport_results schema.

import argparse
import json
import os
import sys
import time
import ctypes as ct

# Allow running as: sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py
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

_KER_MAJOR, _KER_MINOR = _kernel_version()
_RINGBUF_SUPPORTED = (_KER_MAJOR, _KER_MINOR) >= (5, 8)

# ---------------------------------------------------------------------------
# eBPF (C) kernel program templates
# ---------------------------------------------------------------------------

# BPF_PERF_OUTPUT variant.
# PAYLOAD_SIZE is injected at compile time via -DPAYLOAD_SIZE=N in cflags.
_BPF_PERF_OUTPUT_PROG = r"""
#include <linux/sched.h>

// Event struct whose payload field is sized by the compile-time constant
// PAYLOAD_SIZE, injected via BCC cflags (-DPAYLOAD_SIZE=N).
struct event_t {
    u64 kernel_ts;              // bpf_ktime_get_ns() — kernel-side timestamp
    u32 pid;
    char payload[PAYLOAD_SIZE]; // variable-length byte array filled with 0xAB
};

// BPF_PERF_OUTPUT: per-CPU perf ring buffer; delivered via perf_buffer_poll().
BPF_PERF_OUTPUT(events);

int probe_getpid(struct pt_regs *ctx) {
    struct event_t ev = {};

    ev.kernel_ts = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Fill payload with a fixed pattern so the copy path exercises real data.
    // bpf_probe_read_kernel writes N bytes; here we initialise in the stack struct.
#pragma unroll
    for (int i = 0; i < PAYLOAD_SIZE; i++) {
        ev.payload[i] = (char)0xAB;
    }

    // perf_submit() copies the entire struct (header + payload) to the ring buffer.
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""

# BPF_RINGBUF variant (Linux >= 5.8).
_BPF_RINGBUF_PROG = r"""
#include <linux/sched.h>

struct event_t {
    u64 kernel_ts;
    u32 pid;
    char payload[PAYLOAD_SIZE];
};

// BPF_RINGBUF_OUTPUT: single shared ring buffer; more efficient than per-CPU perf buffers.
BPF_RINGBUF_OUTPUT(events, RINGBUF_PAGES);

int probe_getpid(struct pt_regs *ctx) {
    // Reserve space directly in the ring buffer to avoid a double copy.
    struct event_t *ev = events.ringbuf_reserve(sizeof(struct event_t));
    if (!ev) {
        // Ring buffer full: drop this event.
        return 0;
    }

    ev->kernel_ts = bpf_ktime_get_ns();
    ev->pid       = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

#pragma unroll
    for (int i = 0; i < PAYLOAD_SIZE; i++) {
        ev->payload[i] = (char)0xAB;
    }

    events.ringbuf_submit(ev, 0);
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

DEFAULT_SIZES = [8, 32, 64, 128, 256, 512, 1024, 2048, 4096]

parser = argparse.ArgumentParser(
    description="Sweep event payload sizes for BPF_PERF_OUTPUT and BPF_RINGBUF.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument(
    "--events", "-n",
    type=int,
    default=5_000,
    help="Number of events to collect per (transport, payload_size) point",
)
parser.add_argument(
    "--sizes",
    type=str,
    default=",".join(str(s) for s in DEFAULT_SIZES),
    help="Comma-separated list of payload sizes in bytes",
)
parser.add_argument(
    "--ring-pages",
    type=int,
    default=64,
    help="Ring/perf buffer size in pages (must be a power of 2)",
)
parser.add_argument(
    "--output-dir",
    default=os.path.join(os.path.dirname(__file__), "..", "results"),
    help="Directory for .jsonl result files",
)
args = parser.parse_args()

TARGET_EVENTS = args.events
try:
    SIZES = [int(s.strip()) for s in args.sizes.split(",") if s.strip()]
except ValueError as exc:
    print("ERROR: --sizes must be a comma-separated list of integers: %s" % exc,
          file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helper: find a usable kprobe symbol for sys_getpid
# ---------------------------------------------------------------------------

def _find_getpid_sym():
    """Return the first available kprobe symbol for sys_getpid, or None."""
    from bcc import BPF as _BPF
    for sym in ("__x64_sys_getpid", "sys_getpid"):
        if _BPF.ksymname(sym) != 0xFFFFFFFFFFFFFFFF:
            return sym
    return None

# ---------------------------------------------------------------------------
# Benchmark runner for a single (transport, payload_size) data point
# ---------------------------------------------------------------------------

def _run_point_perf_output(payload_size, target_events, ring_pages, getpid_sym):
    """
    Run one BPF_PERF_OUTPUT measurement at a given payload size.
    Returns a dict with latency/throughput stats, or raises on error.
    """
    from bcc import BPF

    latencies_ns = []
    done_flag = [False]

    # Build ctypes struct matching the kernel struct for this payload size.
    class _Event(ct.Structure):
        _fields_ = [
            ("kernel_ts", ct.c_uint64),
            ("pid",       ct.c_uint32),
            ("payload",   ct.c_char * payload_size),
        ]

    def handle_event(cpu, data, size):
        if done_flag[0]:
            return
        recv_ns = time.monotonic_ns()
        ev = ct.cast(data, ct.POINTER(_Event)).contents
        lat = recv_ns - ev.kernel_ts
        if lat > 0:
            latencies_ns.append(lat)
        if len(latencies_ns) >= target_events:
            done_flag[0] = True

    b = BPF(
        text=_BPF_PERF_OUTPUT_PROG,
        cflags=["-DPAYLOAD_SIZE=%d" % payload_size],
    )
    b.attach_kprobe(event=getpid_sym, fn_name="probe_getpid")
    b["events"].open_perf_buffer(handle_event, page_cnt=ring_pages)

    wall_start = time.monotonic()
    try:
        while not done_flag[0]:
            os.getpid()
            b.perf_buffer_poll(timeout=0)
    except KeyboardInterrupt:
        pass
    wall_end = time.monotonic()

    b.detach_kprobe(event=getpid_sym)

    elapsed_sec = wall_end - wall_start
    stats = compute_stats(latencies_ns)
    events_per_sec = stats["count"] / elapsed_sec if elapsed_sec > 0 else 0.0

    return {
        "payload_bytes":   payload_size,
        "count":           stats["count"],
        "mean_ns":         round(stats["mean"],  2),
        "p50_ns":          round(stats["p50"],   2),
        "p95_ns":          round(stats["p95"],   2),
        "p99_ns":          round(stats["p99"],   2),
        "stdev_ns":        round(stats["stdev"], 2),
        "min_ns":          round(stats["min"],   2),
        "max_ns":          round(stats["max"],   2),
        "events_per_sec":  round(events_per_sec, 2),
        "elapsed_sec":     round(elapsed_sec,    4),
    }


def _run_point_ringbuf(payload_size, target_events, ring_pages, getpid_sym):
    """
    Run one BPF_RINGBUF measurement at a given payload size.
    Returns a dict with latency/throughput stats, or raises on error.
    """
    from bcc import BPF

    latencies_ns = []
    done_flag = [False]

    class _Event(ct.Structure):
        _fields_ = [
            ("kernel_ts", ct.c_uint64),
            ("pid",       ct.c_uint32),
            ("payload",   ct.c_char * payload_size),
        ]

    def handle_event(ctx, data, size):
        if done_flag[0]:
            return
        recv_ns = time.monotonic_ns()
        ev = ct.cast(data, ct.POINTER(_Event)).contents
        lat = recv_ns - ev.kernel_ts
        if lat > 0:
            latencies_ns.append(lat)
        if len(latencies_ns) >= target_events:
            done_flag[0] = True

    # Substitute RINGBUF_PAGES at string level (same pattern as bench_ringbuf.py).
    prog = _BPF_RINGBUF_PROG.replace("RINGBUF_PAGES", str(ring_pages))
    b = BPF(
        text=prog,
        cflags=["-DPAYLOAD_SIZE=%d" % payload_size],
    )
    b.attach_kprobe(event=getpid_sym, fn_name="probe_getpid")
    b["events"].open_ring_buffer(handle_event)

    wall_start = time.monotonic()
    try:
        while not done_flag[0]:
            os.getpid()
            b.ring_buffer_poll(timeout=0)
    except KeyboardInterrupt:
        pass
    wall_end = time.monotonic()

    b.detach_kprobe(event=getpid_sym)

    elapsed_sec = wall_end - wall_start
    stats = compute_stats(latencies_ns)
    events_per_sec = stats["count"] / elapsed_sec if elapsed_sec > 0 else 0.0

    return {
        "payload_bytes":   payload_size,
        "count":           stats["count"],
        "mean_ns":         round(stats["mean"],  2),
        "p50_ns":          round(stats["p50"],   2),
        "p95_ns":          round(stats["p95"],   2),
        "p99_ns":          round(stats["p99"],   2),
        "stdev_ns":        round(stats["stdev"], 2),
        "min_ns":          round(stats["min"],   2),
        "max_ns":          round(stats["max"],   2),
        "events_per_sec":  round(events_per_sec, 2),
        "elapsed_sec":     round(elapsed_sec,    4),
    }

# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------

print(
    "bench_payload_sweep: sizes=%s  events_per_point=%d" % (SIZES, TARGET_EVENTS),
    file=sys.stderr,
)

# Locate getpid symbol once (requires bcc import).
try:
    from bcc import BPF as _BPF_CHECK  # noqa: F401
except ImportError:
    print(json.dumps({"error": "BCC not available — install python3-bpfcc"}))
    sys.exit(1)

getpid_sym = _find_getpid_sym()
if getpid_sym is None:
    print(json.dumps({"error": "Could not find a suitable getpid syscall symbol"}))
    sys.exit(1)

transport_results = {
    "BPF_PERF_OUTPUT": [],
    "BPF_RINGBUF":     [],
}

try:
    for sz in SIZES:
        # --- BPF_PERF_OUTPUT ---
        print(
            "  BPF_PERF_OUTPUT  payload=%5d B  collecting %d events …" % (sz, TARGET_EVENTS),
            file=sys.stderr,
        )
        try:
            point = _run_point_perf_output(sz, TARGET_EVENTS, args.ring_pages, getpid_sym)
            transport_results["BPF_PERF_OUTPUT"].append(point)
            print(
                "    → mean=%.0f ns  p99=%.0f ns  tput=%.0f ev/s" % (
                    point["mean_ns"], point["p99_ns"], point["events_per_sec"]
                ),
                file=sys.stderr,
            )
        except Exception as exc:
            print("    ERROR: %s" % exc, file=sys.stderr)
            transport_results["BPF_PERF_OUTPUT"].append(
                {"payload_bytes": sz, "error": str(exc)}
            )

        # --- BPF_RINGBUF ---
        if not _RINGBUF_SUPPORTED:
            print(
                "  BPF_RINGBUF      payload=%5d B  SKIPPED (kernel %d.%d < 5.8)" % (
                    sz, _KER_MAJOR, _KER_MINOR
                ),
                file=sys.stderr,
            )
            transport_results["BPF_RINGBUF"].append({
                "payload_bytes": sz,
                "skipped": True,
                "reason": "Kernel %d.%d < 5.8 — BPF_RINGBUF not available" % (
                    _KER_MAJOR, _KER_MINOR
                ),
            })
            continue

        print(
            "  BPF_RINGBUF      payload=%5d B  collecting %d events …" % (sz, TARGET_EVENTS),
            file=sys.stderr,
        )
        try:
            point = _run_point_ringbuf(sz, TARGET_EVENTS, args.ring_pages, getpid_sym)
            transport_results["BPF_RINGBUF"].append(point)
            print(
                "    → mean=%.0f ns  p99=%.0f ns  tput=%.0f ev/s" % (
                    point["mean_ns"], point["p99_ns"], point["events_per_sec"]
                ),
                file=sys.stderr,
            )
        except Exception as exc:
            print("    ERROR: %s" % exc, file=sys.stderr)
            transport_results["BPF_RINGBUF"].append(
                {"payload_bytes": sz, "error": str(exc)}
            )

except KeyboardInterrupt:
    print("\nInterrupted — emitting partial results.", file=sys.stderr)

# ---------------------------------------------------------------------------
# Emit result
# ---------------------------------------------------------------------------

result = {
    "benchmark":        "bench_payload_sweep",
    "transport_results": transport_results,
}

write_result("bench_payload_sweep", result, output_dir=args.output_dir)
print(json.dumps(result))
