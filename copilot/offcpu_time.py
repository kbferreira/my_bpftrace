#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# offcpu_time.py - Stream off-CPU time events from kernel to userspace via
#                  BPF_PERF_OUTPUT, with live per-process terminal chart and/or
#                  file save (CSV or JSON Lines).
#
# Description:
#   Measures the time each task spends NOT running on a CPU — i.e., the time
#   between being switched out and switched back in.  Each completed off-CPU
#   interval is submitted to userspace as a perf event rather than accumulated
#   in the kernel.  Userspace can display a live line chart that refreshes
#   every --interval seconds, save all raw events to a file, or both.
#
# Usage:
#   sudo python3 offcpu_time.py                         # live chart, run until Ctrl-C
#   sudo python3 offcpu_time.py 30 --top 5              # chart for 30 s, top 5 procs
#   sudo python3 offcpu_time.py --save /tmp/offcpu.csv --no-chart
#   sudo python3 offcpu_time.py -p 1234 --save /tmp/offcpu.jsonl
#   sudo python3 offcpu_time.py 60 -i 2                 # refresh every 2 s, run 60 s
#
# CLI flags:
#   duration            Tracing duration in seconds (default: 0 = run until Ctrl-C)
#   -p / --pid PID      Trace only this PID
#   -i / --interval N   Chart refresh interval in seconds (default: 1)
#   -t / --top N        Show top N processes in chart (default: 10)
#   --save PATH         Save raw events to file (.csv or .json/.jsonl)
#   --no-chart          Disable the live chart
#
# Requirements:
#   - Linux kernel >= 4.9
#   - BCC (BPF Compiler Collection) installed
#     https://github.com/iovisor/bcc/blob/master/INSTALL.md
#   - plotext >= 5.2.8  (pip install plotext)  — only needed for live chart

from bcc import BPF
import argparse
import csv
import json
import os
import sys
import time
from collections import defaultdict

# ---------------------------------------------------------------------------
# eBPF (C) kernel program
# ---------------------------------------------------------------------------

bpf_program = r"""
#include <linux/sched.h>

struct event_t {
    u32  pid;
    char comm[TASK_COMM_LEN];
    u64  offcpu_ns;   // duration of this off-CPU interval in nanoseconds
    u64  ts;          // kernel timestamp when task came back ON cpu
};

// Map: pid -> timestamp when the task was switched OUT
BPF_HASH(start, u32, u64);

// Perf output channel: completed off-CPU events streamed to userspace
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_switch) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    // --- task being switched OUT: record start timestamp ---
    FILTER_PREV
    start.update(&prev_pid, &ts);

    // --- task being switched IN: compute delta and emit event ---
    u64 *tsp = start.lookup(&next_pid);
    if (tsp == 0) {
        return 0;
    }

    // Guard against timestamp wraparound
    if (ts <= *tsp) {
        start.delete(&next_pid);
        return 0;
    }

    u64 delta = ts - *tsp;
    start.delete(&next_pid);

    FILTER_NEXT

    struct event_t ev = {};
    ev.pid       = next_pid;
    ev.offcpu_ns = delta;
    ev.ts        = ts;
    bpf_probe_read_kernel_str(ev.comm, sizeof(ev.comm), args->next_comm);

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Trace off-CPU time for Linux tasks (streaming via BPF_PERF_OUTPUT)."
)
parser.add_argument(
    "duration",
    nargs="?",
    default=0,
    type=int,
    help="Tracing duration in seconds (default: 0 = run until Ctrl-C)",
)
parser.add_argument(
    "-p", "--pid",
    type=int,
    default=None,
    help="Trace only this PID",
)
parser.add_argument(
    "-i", "--interval",
    type=float,
    default=1.0,
    metavar="SECS",
    help="Chart refresh interval in seconds (default: 1)",
)
parser.add_argument(
    "-t", "--top",
    type=int,
    default=10,
    metavar="N",
    help="Show top N processes in chart (default: 10)",
)
parser.add_argument(
    "--save",
    metavar="PATH",
    default=None,
    help="Save raw events to this file (.csv or .json/.jsonl)",
)
parser.add_argument(
    "--no-chart",
    action="store_true",
    help="Disable the live chart",
)
args = parser.parse_args()

# ---------------------------------------------------------------------------
# Inject optional PID filter into the eBPF source
# ---------------------------------------------------------------------------

if args.pid is not None:
    filter_prev = "if (prev_pid != %d) { return 0; }" % args.pid
    filter_next = "if (next_pid != %d) { return 0; }" % args.pid
else:
    filter_prev = ""
    filter_next = ""

bpf_program = bpf_program.replace("FILTER_PREV", filter_prev)
bpf_program = bpf_program.replace("FILTER_NEXT", filter_next)

# ---------------------------------------------------------------------------
# plotext availability check
# ---------------------------------------------------------------------------

USE_CHART = not args.no_chart
try:
    import plotext as plt
except ImportError:
    if USE_CHART:
        print(
            "Warning: plotext is not installed. "
            "Install it with: pip install plotext\n"
            "Falling back to text-table mode.",
            file=sys.stderr,
        )
    plt = None
    USE_CHART = False  # fall back to text-table refreshes

# ---------------------------------------------------------------------------
# File output setup
# ---------------------------------------------------------------------------

save_file = None
csv_writer = None

if args.save:
    path = args.save
    ext = os.path.splitext(path)[1].lower()
    save_file = open(path, "w", buffering=1)  # line-buffered
    if ext == ".csv":
        csv_writer = csv.writer(save_file)
        csv_writer.writerow(["timestamp_s", "pid", "comm", "offcpu_ms"])
    elif ext in (".json", ".jsonl"):
        pass  # JSON Lines: write one object per line directly
    else:
        print(
            "Warning: unrecognised file extension '%s'. "
            "Writing JSON Lines format." % ext,
            file=sys.stderr,
        )

# ---------------------------------------------------------------------------
# In-memory event store: { (pid, comm): [(wall_clock_s, offcpu_ms), ...] }
# ---------------------------------------------------------------------------

samples: dict[tuple, list] = defaultdict(list)
start_wall = time.time()

# ---------------------------------------------------------------------------
# Load and attach BPF program
# ---------------------------------------------------------------------------

b = BPF(text=bpf_program)
# TRACEPOINT_PROBE is attached automatically.

# ---------------------------------------------------------------------------
# Perf-buffer callback (runs in polling loop — must be fast / non-blocking)
# ---------------------------------------------------------------------------

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    pid       = event.pid
    comm      = event.comm.decode("utf-8", errors="replace").rstrip("\x00")
    offcpu_ms = event.offcpu_ns / 1_000_000.0
    wall_s    = time.time() - start_wall

    samples[(pid, comm)].append((wall_s, offcpu_ms))

    if save_file is not None:
        timestamp_s = start_wall + wall_s
        if csv_writer is not None:
            csv_writer.writerow([
                round(timestamp_s, 6), pid, comm, round(offcpu_ms, 6)
            ])
        else:
            save_file.write(
                json.dumps({
                    "timestamp_s": round(timestamp_s, 6),
                    "pid": pid,
                    "comm": comm,
                    "offcpu_ms": round(offcpu_ms, 6),
                }) + "\n"
            )

b["events"].open_perf_buffer(handle_event)

# ---------------------------------------------------------------------------
# Chart / table refresh helpers
# ---------------------------------------------------------------------------

def _top_keys_by_total(n):
    """Return the top-n (pid, comm) keys ranked by cumulative off-CPU ms."""
    totals = {k: sum(v for _, v in pts) for k, pts in samples.items()}
    return sorted(totals, key=totals.__getitem__, reverse=True)[:n]


def draw_chart(elapsed_s):
    """Redraw the plotext line chart with all accumulated data."""
    plt.clf()
    plt.title("Off-CPU time — elapsed %.1f s" % elapsed_s)
    plt.xlabel("Elapsed seconds")
    plt.ylabel("Off-CPU ms (per event)")

    top_keys = _top_keys_by_total(args.top)

    for (pid, comm) in top_keys:
        all_pts = samples[(pid, comm)]
        if not all_pts:
            continue
        xs = [t for t, _ in all_pts]
        ys = [v for _, v in all_pts]
        plt.plot(xs, ys, label="%s(%d)" % (comm, pid))

    plt.show()


def print_table(interval_s, elapsed_s):
    """Print a text table of per-process off-CPU totals (fallback mode)."""
    window_start = elapsed_s - interval_s
    top_keys = _top_keys_by_total(args.top)
    print("\n--- Off-CPU snapshot @ %.1f s (last %.1f s) ---" % (elapsed_s, interval_s))
    print("%-6s %-16s %s" % ("PID", "COMM", "OFF-CPU MS (interval)"))
    for (pid, comm) in top_keys:
        interval_ms = sum(
            v for t, v in samples[(pid, comm)] if t >= window_start
        )
        if interval_ms > 0:
            print("%-6d %-16s %.2f" % (pid, comm, interval_ms))


def print_summary():
    """Print a final summary table sorted by total off-CPU time."""
    print()
    print("=== Final summary ===")
    print("%-6s %-16s %s" % ("PID", "COMM", "TOTAL OFF-CPU TIME (ms)"))
    totals = {k: sum(v for _, v in pts) for k, pts in samples.items()}
    for (pid, comm), total_ms in sorted(totals.items(), key=lambda x: x[1], reverse=True):
        print("%-6d %-16s %.2f" % (pid, comm, total_ms))

# ---------------------------------------------------------------------------
# Main event loop
# ---------------------------------------------------------------------------

duration_msg = (
    "run until Ctrl-C" if args.duration == 0
    else "%d seconds" % args.duration
)
print("Tracing off-CPU time... %s." % duration_msg)
if USE_CHART:
    print("Live chart refreshes every %.1f s.  Ctrl-C to stop." % args.interval)

next_refresh = time.time() + args.interval
end_time = (time.time() + args.duration) if args.duration > 0 else None

try:
    while True:
        now = time.time()
        if end_time is not None and now >= end_time:
            break

        # Drain available perf events (non-blocking poll, 100 ms timeout)
        b.perf_buffer_poll(timeout=100)

        now = time.time()
        if now >= next_refresh:
            elapsed_s = now - start_wall
            if USE_CHART:
                draw_chart(elapsed_s)
            else:
                print_table(args.interval, elapsed_s)
            next_refresh = now + args.interval

except KeyboardInterrupt:
    pass
finally:
    if save_file is not None:
        save_file.close()

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------

print_summary()
