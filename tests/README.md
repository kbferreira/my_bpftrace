# eBPF Kernel→Userspace Overhead Benchmark Suite

This directory contains a comprehensive test suite that **quantifies the overhead of passing data from kernel space to userspace** using eBPF via [BCC (bcc-python)](https://github.com/iovisor/bcc).

The suite benchmarks five common kernel-to-userspace transport mechanisms and produces structured, comparable metrics (latency, throughput, CPU overhead).

---

## Prerequisites

| Requirement | Version / Notes |
|---|---|
| Linux kernel | ≥ 4.9 (≥ 5.8 for `bench_ringbuf`) |
| BCC (bcc-python) | ≥ 0.29.0 — [install guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md) |
| Python | ≥ 3.8 |
| Root access | Required — eBPF programs require `CAP_BPF` / root |
| `debugfs` mounted | Required for `bench_trace_printk` (`/sys/kernel/debug/tracing/trace_pipe`) |

### Install Python dependencies

```bash
pip3 install -r tests/requirements.txt
```

> **Note:** BCC itself is typically installed as a system package (e.g., `apt install python3-bpfcc` on Ubuntu) rather than via pip. The `bcc` entry in `requirements.txt` is for documentation purposes.

---

## Running the Benchmarks

### Run the full suite (recommended)

```bash
sudo python3 tests/run_all.py
```

This runs all five benchmarks sequentially, prints a Markdown summary table, and saves a combined JSON report to `tests/results/summary_<timestamp>.json`.

#### Options

```
--duration N     Duration in seconds per benchmark (default: 5)
--events N       Target event count for latency benchmarks (default: 10000)
--output-dir DIR Directory for result files (default: tests/results/)
```

Example:

```bash
sudo python3 tests/run_all.py --duration 10 --events 50000
```

---

### Run individual benchmarks

Each benchmark is independently runnable:

```bash
sudo python3 tests/bench_perf_output/bench_perf_output.py
sudo python3 tests/bench_ringbuf/bench_ringbuf.py
sudo python3 tests/bench_hash_map/bench_hash_map.py
sudo python3 tests/bench_array_map/bench_array_map.py
sudo python3 tests/bench_trace_printk/bench_trace_printk.py
```

Each script emits a **single JSON object to stdout** on completion. Pass `--help` for available options.

---

## Benchmark Reference

| Benchmark | Transport | Attach Point | What It Measures | When to Prefer |
|---|---|---|---|---|
| `bench_perf_output` | `BPF_PERF_OUTPUT` | `kprobe/sys_getpid` | Per-event kernel→userspace latency via per-CPU perf ring buffers | High-frequency event streaming; needs low-latency delivery |
| `bench_ringbuf` | `BPF_RINGBUF` | `kprobe/sys_getpid` | Per-event latency via single shared ring buffer (Linux ≥ 5.8) | Modern kernels; lower overhead than `BPF_PERF_OUTPUT`; in-order delivery |
| `bench_hash_map` | `BPF_HASH` | `sched:sched_switch` | Map iteration round-trip latency; poll-based read-back cost | Aggregating data kernel-side; infrequent userspace reads |
| `bench_array_map` | `BPF_ARRAY` | `sched:sched_switch` | Single-counter read latency; increment rate | Counters/histograms; simplest poll-based approach |
| `bench_trace_printk` | `bpf_trace_printk` | `sched:sched_switch` | Pipe throughput and end-to-end delivery latency (baseline/worst-case) | Debugging only; not for production |

---

## Interpreting the Metrics

### Latency benchmarks (`bench_perf_output`, `bench_ringbuf`)

| Metric | Meaning |
|---|---|
| `mean_ns` | Average kernel→userspace delivery time. On an idle system this is typically 3–10 µs. |
| `p50_ns` | Median latency — representative of the typical case. |
| `p95_ns` | 95th percentile — captures occasional spikes. |
| `p99_ns` | 99th percentile — indicates tail latency. A high ratio of p99/mean suggests scheduling jitter or ring-buffer back-pressure. |
| `stdev_ns` | Spread of latency distribution. High stdev = unstable delivery times. |
| `events_per_sec` | Combined throughput: syscall + kprobe + ring-buffer copy + poll wakeup + Python callback. |

**What high P99 latency in `bench_perf_output` implies:**  
A large gap between `p50_ns` and `p99_ns` usually means the perf ring buffer is occasionally full (back-pressure from a slow consumer) or the OS scheduler delayed the Python polling loop. Run on an otherwise-idle system and increase `page_cnt` to reduce back-pressure.

### Poll-based benchmarks (`bench_hash_map`, `bench_array_map`)

| Metric | Meaning |
|---|---|
| `mean_read_latency_us` | Time to perform one complete map read from userspace (via `bpf()` syscall). |
| `poll_count` | Number of reads completed in the run duration. |
| `total_events_read` / `total_increments` | Kernel-side event count — reflects system activity level. |
| `increment_rate_per_sec` | Context-switch rate observed during the run (array map only). |

**BPF_HASH vs BPF_ARRAY:**  
`BPF_ARRAY` reads a single slot (one `bpf(BPF_MAP_LOOKUP_ELEM)` call, ~3 µs). `BPF_HASH` iterates all entries (`bpf(BPF_MAP_GET_NEXT_KEY)` + `bpf(BPF_MAP_LOOKUP_ELEM)` per entry), so `mean_read_latency_us` scales linearly with `map_entries`.

### Trace pipe benchmark (`bench_trace_printk`)

| Metric | Meaning |
|---|---|
| `lines_received` | Total lines read from `trace_pipe`. |
| `lines_per_sec` | Pipe throughput — limited by kernel rate-limiting. |
| `mean_pipe_latency_ns` | Average time from `bpf_trace_printk` call to Python readline(). Typically 100 µs–1 ms. |
| `p99_pipe_latency_ns` | Tail latency — often in the millisecond range due to pipe buffering. |

---

## Known Limitations

1. **`bpf_trace_printk` is kernel-throttled** to approximately 1 message per 5 µs per CPU. On busy systems many events are silently dropped, making throughput measurements a lower bound.

2. **`BPF_RINGBUF` requires Linux ≥ 5.8.** On older kernels `bench_ringbuf.py` exits cleanly with a skip message and exit code 0.

3. **Clock alignment:** Latency measurements compare `bpf_ktime_get_ns()` (CLOCK_MONOTONIC in the kernel) with `time.monotonic_ns()` in Python. These are the same clock source and should be directly comparable, but small offsets may appear on multi-socket NUMA systems.

4. **Root required:** All benchmarks must be run as root (or with `CAP_BPF` + `CAP_PERFMON` + `CAP_TRACING` on kernels ≥ 5.8).

5. **System load affects results:** Run benchmarks on a lightly loaded system for the most reproducible results. A busy system increases `p99` values significantly.

6. **BCC version:** Different BCC versions may expose different Python APIs. The benchmarks target BCC ≥ 0.29.0. `BPF_RINGBUF_OUTPUT` was added in BCC 0.25.0.

7. **Architecture:** The `kprobe` used in `bench_perf_output` and `bench_ringbuf` targets `__x64_sys_getpid` (x86-64). On other architectures (ARM64, etc.) the symbol name may differ; the scripts fall back to `sys_getpid` automatically.

---

## Directory Structure

```
tests/
├── README.md                        # This file
├── requirements.txt                 # Python deps
├── run_all.py                       # Orchestrator
│
├── lib/
│   └── bench_utils.py               # Shared helpers (stats, timer, JSON writer)
│
├── bench_perf_output/
│   ├── bench_perf_output.py
│   └── expected_output.txt
│
├── bench_ringbuf/
│   ├── bench_ringbuf.py
│   └── expected_output.txt
│
├── bench_hash_map/
│   ├── bench_hash_map.py
│   └── expected_output.txt
│
├── bench_array_map/
│   ├── bench_array_map.py
│   └── expected_output.txt
│
└── bench_trace_printk/
    ├── bench_trace_printk.py
    └── expected_output.txt
```

Results are written to `tests/results/` (created automatically):

- `<benchmark_name>.jsonl` — append-only JSON-lines log for trend analysis
- `summary_<timestamp>.json` — combined run summary from `run_all.py`
