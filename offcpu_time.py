#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# offcpu_time.py - Trace off-CPU time for Linux tasks using BCC (eBPF).
#
# Description:
#   Measures the time each task spends NOT running on a CPU — i.e., the time
#   between being switched out and switched back in. This is useful for
#   diagnosing latency caused by scheduling delays, I/O waits, lock contention,
#   or any other reason a process is blocked rather than executing.
#
# Usage:
#   sudo python3 offcpu_time.py              # trace all PIDs for 10 seconds
#   sudo python3 offcpu_time.py 5            # trace all PIDs for 5 seconds
#   sudo python3 offcpu_time.py -p 1234      # trace only PID 1234 for 10 s
#   sudo python3 offcpu_time.py -p 1234 5    # trace PID 1234 for 5 seconds
#
# Requirements:
#   - Linux kernel >= 4.9
#   - BCC (BPF Compiler Collection) installed
#     https://github.com/iovisor/bcc/blob/master/INSTALL.md

from bcc import BPF
import argparse
import time
import ctypes as ct

# ---------------------------------------------------------------------------
# eBPF (C) kernel program
# ---------------------------------------------------------------------------

bpf_program = r"""
#include <linux/sched.h>

struct off_key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

// Map: pid -> timestamp when the task was switched OUT
BPF_HASH(start, u32, u64);

// Map: (pid, comm) -> accumulated off-CPU nanoseconds
BPF_HASH(off_cpu, struct off_key_t, u64);

TRACEPOINT_PROBE(sched, sched_switch) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    // --- task being switched OUT: record start timestamp ---
    FILTER_PREV
    start.update(&prev_pid, &ts);

    // --- task being switched IN: compute delta and accumulate ---
    u64 *tsp = start.lookup(&next_pid);
    if (tsp == 0) {
        return 0;
    }

    // Guard against timestamp wraparound: skip if start is ahead of now.
    if (ts <= *tsp) {
        start.delete(&next_pid);
        return 0;
    }

    u64 delta = ts - *tsp;
    start.delete(&next_pid);

    FILTER_NEXT

    struct off_key_t key = {};
    key.pid = next_pid;
    bpf_probe_read_kernel_str(key.comm, sizeof(key.comm), args->next_comm);

    u64 *val = off_cpu.lookup(&key);
    if (val) {
        *val += delta;
    } else {
        off_cpu.update(&key, &delta);
    }

    return 0;
}
"""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Trace off-CPU time for Linux tasks."
)
parser.add_argument(
    "duration",
    nargs="?",
    default=10,
    type=int,
    help="Duration in seconds to trace (default: 10)",
)
parser.add_argument(
    "-p",
    "--pid",
    type=int,
    default=None,
    help="Trace only this PID",
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
# Load and attach BPF program
# ---------------------------------------------------------------------------

b = BPF(text=bpf_program)
# The tracepoint is attached automatically via TRACEPOINT_PROBE macro.

print("Tracing off-CPU time... Hit Ctrl-C or wait %d seconds." % args.duration)

try:
    time.sleep(args.duration)
except KeyboardInterrupt:
    pass

# ---------------------------------------------------------------------------
# Read and display results
# ---------------------------------------------------------------------------

off_cpu_map = b["off_cpu"]

rows = []
for k, v in off_cpu_map.items():
    pid = k.pid
    comm = k.comm.decode("utf-8", errors="replace")
    offcpu_ms = round(v.value / 1_000_000, 2)
    rows.append((pid, comm, offcpu_ms))

# Sort by off-CPU time descending
rows.sort(key=lambda r: r[2], reverse=True)

print()
print("%-6s %-16s %s" % ("PID", "COMM", "OFF-CPU TIME (ms)"))
for pid, comm, offcpu_ms in rows:
    print("%-6d %-16s %.2f" % (pid, comm, offcpu_ms))
