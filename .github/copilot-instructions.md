# Copilot Instructions

## Project Overview

This repository contains Python scripts that use [BCC (BPF Compiler Collection)](https://github.com/iovisor/bcc) to write and run eBPF programs on Linux. The scripts trace kernel events (e.g., scheduler switches) and measure kernel→userspace data-transport overhead across different eBPF mechanisms.

Key files:
- `hello.sched_switch.py` — introductory BCC script that attaches to the `sched:sched_switch` tracepoint and logs context-switch events via `bpf_trace_printk`.
- `copilot/offcpu_time.py` — measures per-task off-CPU time using `TRACEPOINT_PROBE(sched, sched_switch)` and a `BPF_HASH` accumulator map.
- `tests/` — benchmark suite that quantifies kernel→userspace overhead for five transport mechanisms (`BPF_PERF_OUTPUT`, `BPF_RINGBUF`, `BPF_HASH`, `BPF_ARRAY`, `bpf_trace_printk`) plus three sweep benchmarks (payload size, event rate, map size).

## Tech Stack

- **Language:** Python 3.8+
- **eBPF runtime:** [BCC (bcc-python)](https://github.com/iovisor/bcc) ≥ 0.29.0
- **Kernel requirement:** Linux ≥ 4.9 (≥ 5.8 for `BPF_RINGBUF`)
- **Python dependencies:** `numpy>=1.21.0` (see `tests/requirements.txt`)
- **Privilege:** All scripts must be run as root (or with `CAP_BPF` + `CAP_PERFMON` + `CAP_TRACING`)

## Development Environment Setup

1. Install BCC as a system package:
   ```bash
   # Ubuntu/Debian
   sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
   ```
2. Install Python dependencies:
   ```bash
   pip3 install -r tests/requirements.txt
   ```
3. Verify your kernel version is ≥ 4.9:
   ```bash
   uname -r
   ```

## Running Scripts

All scripts require root:

```bash
# Introductory tracepoint example
sudo python3 hello.sched_switch.py

# Off-CPU time tracer
sudo python3 copilot/offcpu_time.py            # trace all PIDs for 10 s
sudo python3 copilot/offcpu_time.py 5          # trace for 5 s
sudo python3 copilot/offcpu_time.py -p 1234    # trace only PID 1234
```

## Running the Benchmark Suite

```bash
# Full suite (recommended)
sudo python3 tests/run_all.py

# With options
sudo python3 tests/run_all.py --duration 10 --events 50000

# Individual benchmarks
sudo python3 tests/bench_perf_output/bench_perf_output.py
sudo python3 tests/bench_ringbuf/bench_ringbuf.py
sudo python3 tests/bench_hash_map/bench_hash_map.py
sudo python3 tests/bench_array_map/bench_array_map.py
sudo python3 tests/bench_trace_printk/bench_trace_printk.py
sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py
sudo python3 tests/bench_event_rate_sweep/bench_event_rate_sweep.py
sudo python3 tests/bench_map_size_sweep/bench_map_size_sweep.py
```

Each individual benchmark script outputs a single JSON object to stdout on completion. Use `--help` for available options.

## Code Conventions

- **File encoding header:** All Python files use `# -*- coding: utf-8 -*-`.
- **eBPF C code** is embedded as raw strings (`r"""..."""`) inside Python files.
- **BCC macros** (`BPF_HASH`, `BPF_PERF_OUTPUT`, `BPF_RINGBUF_OUTPUT`, `TRACEPOINT_PROBE`) are preferred over raw `bpf()` syscall wrappers.
- **Tracepoint attachment** is done via `TRACEPOINT_PROBE(subsystem, event_name)` (auto-attached) or `bpf_ctx.attach_tracepoint(tp=..., fn_name=...)`.
- **Benchmark scripts** must emit a single JSON object to stdout as their last non-empty line; all progress/diagnostic output goes to stderr.
- **Results** are written to `tests/results/` (excluded from version control via `.gitignore`).

## Important Notes

- `bpf_trace_printk` is kernel-throttled (~1 message per 5 µs per CPU) and is for debugging only, not production use.
- `BPF_RINGBUF` requires Linux ≥ 5.8; scripts fall back gracefully on older kernels.
- Latency is measured using `bpf_ktime_get_ns()` (kernel) vs `time.monotonic_ns()` (Python) — both use `CLOCK_MONOTONIC`.
- Run benchmarks on a lightly loaded system for reproducible results.
