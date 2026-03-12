#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# bench_event_rate_sweep.py - Sweep event generation rates for BPF_PERF_OUTPUT and BPF_RINGBUF.
#
# Methodology:
#   Payload is fixed at 256 bytes (FIXED_PAYLOAD_BYTES).  For each target rate
#   (events/sec) userspace inserts a sleep of (1/rate) seconds between each
#   os.getpid() call and runs for a fixed window (default: 3 s).
#
#   The number of events received by userspace vs. the number generated is used
#   to estimate the drop count:
#     - BPF_PERF_OUTPUT: drop count comes from the perf_buffer_lost callback.
#     - BPF_RINGBUF:     drop count is inferred from (generated - received).
#
#   BPF_RINGBUF points are skipped on kernels < 5.8.
#
# Usage:
#   sudo python3 tests/bench_event_rate_sweep/bench_event_rate_sweep.py
#   sudo python3 tests/bench_event_rate_sweep/bench_event_rate_sweep.py --window 5
#   sudo python3 tests/bench_event_rate_sweep/bench_event_rate_sweep.py \
#       --rates 1000,10000,100000 --output-dir /tmp/results
#
# Output (stdout): single JSON object with transport_results schema.

import argparse
import json
import os
import sys
import time
import ctypes as ct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from bench_utils import compute_stats, write_result

# ---------------------------------------------------------------------------
# Kernel version check
# ---------------------------------------------------------------------------

def _kernel_version():
    """Return (major, minor) of the running kernel."""
    with open("/proc/version") as fh:
        version_str = fh.read().split()[2]
    parts = version_str.split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return 0, 0

_KER_MAJOR, _KER_MINOR = _kernel_version()
_RINGBUF_SUPPORTED = (_KER_MAJOR, _KER_MINOR) >= (5, 8)

# Fixed payload size for this benchmark.
FIXED_PAYLOAD_BYTES = 256

# ---------------------------------------------------------------------------
# eBPF (C) kernel program templates
# ---------------------------------------------------------------------------

_BPF_PERF_OUTPUT_PROG = r"""
#include <linux/sched.h>

struct event_t {
    u64 kernel_ts;
    u32 pid;
    char payload[PAYLOAD_SIZE];
};

BPF_PERF_OUTPUT(events);

int probe_getpid(struct pt_regs *ctx) {
    struct event_t ev = {};
    ev.kernel_ts = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
#pragma unroll
    for (int i = 0; i < PAYLOAD_SIZE; i++) {
        ev.payload[i] = (char)0xAB;
    }
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""

_BPF_RINGBUF_PROG = r"""
#include <linux/sched.h>

struct event_t {
    u64 kernel_ts;
    u32 pid;
    char payload[PAYLOAD_SIZE];
};

BPF_RINGBUF_OUTPUT(events, RINGBUF_PAGES);

int probe_getpid(struct pt_regs *ctx) {
    struct event_t *ev = events.ringbuf_reserve(sizeof(struct event_t));
    if (!ev) {
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

DEFAULT_RATES = [1000, 5000, 10000, 50000, 100000, 250000, 500000]

# Subtract a small epsilon (100 ns) from sleep intervals to compensate for
# the overhead of the sleep() call itself, keeping achieved rates close to targets.
SLEEP_EPSILON_SEC = 1e-7   # 100 nanoseconds

parser = argparse.ArgumentParser(
    description="Sweep event generation rates for BPF_PERF_OUTPUT and BPF_RINGBUF.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument(
    "--window",
    type=float,
    default=3.0,
    help="Measurement window in seconds per rate step",
)
parser.add_argument(
    "--rates",
    type=str,
    default=",".join(str(r) for r in DEFAULT_RATES),
    help="Comma-separated list of target event rates (events/sec)",
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

WINDOW_SEC = args.window
try:
    RATES = [int(r.strip()) for r in args.rates.split(",") if r.strip()]
except ValueError as exc:
    print("ERROR: --rates must be a comma-separated list of integers: %s" % exc,
          file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helper: ctypes Event struct for fixed payload size
# ---------------------------------------------------------------------------

class _Event(ct.Structure):
    _fields_ = [
        ("kernel_ts", ct.c_uint64),
        ("pid",       ct.c_uint32),
        ("payload",   ct.c_char * FIXED_PAYLOAD_BYTES),
    ]

# ---------------------------------------------------------------------------
# Helper: find getpid kprobe symbol
# ---------------------------------------------------------------------------

def _find_getpid_sym():
    from bcc import BPF as _BPF
    for sym in ("__x64_sys_getpid", "sys_getpid"):
        if _BPF.ksymname(sym) != 0xFFFFFFFFFFFFFFFF:
            return sym
    return None

# ---------------------------------------------------------------------------
# Benchmark runners
# ---------------------------------------------------------------------------

def _run_rate_perf_output(target_rate, window_sec, ring_pages, getpid_sym):
    """
    Run one BPF_PERF_OUTPUT window at the given target event rate.
    Returns a result dict.
    """
    from bcc import BPF

    latencies_ns = []
    received = [0]
    lost = [0]

    def handle_event(cpu, data, size):
        recv_ns = time.monotonic_ns()
        ev = ct.cast(data, ct.POINTER(_Event)).contents
        lat = recv_ns - ev.kernel_ts
        if lat > 0:
            latencies_ns.append(lat)
        received[0] += 1

    def handle_lost(lost_cnt):
        # Called by BCC when the perf ring buffer is full and events are dropped.
        lost[0] += lost_cnt

    b = BPF(
        text=_BPF_PERF_OUTPUT_PROG,
        cflags=["-DPAYLOAD_SIZE=%d" % FIXED_PAYLOAD_BYTES],
    )
    b.attach_kprobe(event=getpid_sym, fn_name="probe_getpid")
    b["events"].open_perf_buffer(handle_event, page_cnt=ring_pages, lost_cb=handle_lost)

    # Sleep interval between getpid() calls to achieve target_rate events/sec.
    # For very high rates the computed interval falls below 0 and we use a tight loop.
    sleep_interval = max(0.0, 1.0 / target_rate - SLEEP_EPSILON_SEC)
    generated = 0

    deadline = time.monotonic() + window_sec
    wall_start = time.monotonic()
    try:
        while time.monotonic() < deadline:
            os.getpid()
            generated += 1
            b.perf_buffer_poll(timeout=0)
            if sleep_interval > 0:
                time.sleep(sleep_interval)
    except KeyboardInterrupt:
        pass
    wall_end = time.monotonic()

    # Final drain: poll once more to collect any buffered events.
    b.perf_buffer_poll(timeout=10)

    b.detach_kprobe(event=getpid_sym)

    actual_window = wall_end - wall_start
    rec = received[0]
    dropped = lost[0]
    # Also count unreceived events not attributed to perf_lost.
    kernel_drops = max(0, generated - rec - dropped)
    total_dropped = dropped + kernel_drops
    drop_rate_pct = (total_dropped / generated * 100.0) if generated > 0 else 0.0
    events_per_sec = rec / actual_window if actual_window > 0 else 0.0

    stats = compute_stats(latencies_ns)

    return {
        "target_rate_per_sec": target_rate,
        "received_events":     rec,
        "dropped_events":      total_dropped,
        "drop_rate_pct":       round(drop_rate_pct, 4),
        "mean_ns":             round(stats["mean"],  2),
        "p99_ns":              round(stats["p99"],   2),
        "events_per_sec":      round(events_per_sec, 2),
        "window_sec":          round(actual_window,  3),
    }


def _run_rate_ringbuf(target_rate, window_sec, ring_pages, getpid_sym):
    """
    Run one BPF_RINGBUF window at the given target event rate.
    Returns a result dict.
    """
    from bcc import BPF

    latencies_ns = []
    received = [0]

    def handle_event(ctx, data, size):
        recv_ns = time.monotonic_ns()
        ev = ct.cast(data, ct.POINTER(_Event)).contents
        lat = recv_ns - ev.kernel_ts
        if lat > 0:
            latencies_ns.append(lat)
        received[0] += 1

    prog = _BPF_RINGBUF_PROG.replace("RINGBUF_PAGES", str(ring_pages))
    b = BPF(
        text=prog,
        cflags=["-DPAYLOAD_SIZE=%d" % FIXED_PAYLOAD_BYTES],
    )
    b.attach_kprobe(event=getpid_sym, fn_name="probe_getpid")
    b["events"].open_ring_buffer(handle_event)

    sleep_interval = max(0.0, 1.0 / target_rate - SLEEP_EPSILON_SEC)
    generated = 0

    deadline = time.monotonic() + window_sec
    wall_start = time.monotonic()
    try:
        while time.monotonic() < deadline:
            os.getpid()
            generated += 1
            b.ring_buffer_poll(timeout=0)
            if sleep_interval > 0:
                time.sleep(sleep_interval)
    except KeyboardInterrupt:
        pass
    wall_end = time.monotonic()

    # Final drain.
    b.ring_buffer_poll(timeout=10)

    b.detach_kprobe(event=getpid_sym)

    actual_window = wall_end - wall_start
    rec = received[0]
    # For ringbuf, infer drops from the difference between generated and received.
    total_dropped = max(0, generated - rec)
    drop_rate_pct = (total_dropped / generated * 100.0) if generated > 0 else 0.0
    events_per_sec = rec / actual_window if actual_window > 0 else 0.0

    stats = compute_stats(latencies_ns)

    return {
        "target_rate_per_sec": target_rate,
        "received_events":     rec,
        "dropped_events":      total_dropped,
        "drop_rate_pct":       round(drop_rate_pct, 4),
        "mean_ns":             round(stats["mean"],  2),
        "p99_ns":              round(stats["p99"],   2),
        "events_per_sec":      round(events_per_sec, 2),
        "window_sec":          round(actual_window,  3),
    }

# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------

print(
    "bench_event_rate_sweep: rates=%s  window=%.1f s  payload=%d B" % (
        RATES, WINDOW_SEC, FIXED_PAYLOAD_BYTES
    ),
    file=sys.stderr,
)

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
    for rate in RATES:
        # --- BPF_PERF_OUTPUT ---
        print(
            "  BPF_PERF_OUTPUT  rate=%7d ev/s  window=%.1f s …" % (rate, WINDOW_SEC),
            file=sys.stderr,
        )
        try:
            point = _run_rate_perf_output(rate, WINDOW_SEC, args.ring_pages, getpid_sym)
            transport_results["BPF_PERF_OUTPUT"].append(point)
            print(
                "    → recv=%d  drop=%d (%.2f%%)  mean=%.0f ns  tput=%.0f ev/s" % (
                    point["received_events"], point["dropped_events"],
                    point["drop_rate_pct"], point["mean_ns"], point["events_per_sec"]
                ),
                file=sys.stderr,
            )
        except Exception as exc:
            print("    ERROR: %s" % exc, file=sys.stderr)
            transport_results["BPF_PERF_OUTPUT"].append(
                {"target_rate_per_sec": rate, "error": str(exc)}
            )

        # --- BPF_RINGBUF ---
        if not _RINGBUF_SUPPORTED:
            print(
                "  BPF_RINGBUF      rate=%7d ev/s  SKIPPED (kernel %d.%d < 5.8)" % (
                    rate, _KER_MAJOR, _KER_MINOR
                ),
                file=sys.stderr,
            )
            transport_results["BPF_RINGBUF"].append({
                "target_rate_per_sec": rate,
                "skipped": True,
                "reason": "Kernel %d.%d < 5.8 — BPF_RINGBUF not available" % (
                    _KER_MAJOR, _KER_MINOR
                ),
            })
            continue

        print(
            "  BPF_RINGBUF      rate=%7d ev/s  window=%.1f s …" % (rate, WINDOW_SEC),
            file=sys.stderr,
        )
        try:
            point = _run_rate_ringbuf(rate, WINDOW_SEC, args.ring_pages, getpid_sym)
            transport_results["BPF_RINGBUF"].append(point)
            print(
                "    → recv=%d  drop=%d (%.2f%%)  mean=%.0f ns  tput=%.0f ev/s" % (
                    point["received_events"], point["dropped_events"],
                    point["drop_rate_pct"], point["mean_ns"], point["events_per_sec"]
                ),
                file=sys.stderr,
            )
        except Exception as exc:
            print("    ERROR: %s" % exc, file=sys.stderr)
            transport_results["BPF_RINGBUF"].append(
                {"target_rate_per_sec": rate, "error": str(exc)}
            )

except KeyboardInterrupt:
    print("\nInterrupted — emitting partial results.", file=sys.stderr)

# ---------------------------------------------------------------------------
# Emit result
# ---------------------------------------------------------------------------

result = {
    "benchmark":        "bench_event_rate_sweep",
    "payload_bytes":    FIXED_PAYLOAD_BYTES,
    "transport_results": transport_results,
}

write_result("bench_event_rate_sweep", result, output_dir=args.output_dir)
print(json.dumps(result))
