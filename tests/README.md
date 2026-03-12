# eBPF Kernel→Userspace Overhead Benchmark Suite

This directory contains a comprehensive test suite that **quantifies the overhead of passing data from kernel space to userspace** using eBPF via [BCC (bcc-python)](https://github.com/iovisor/bcc).

The suite benchmarks five common kernel-to-userspace transport mechanisms and produces structured, comparable metrics (latency, throughput, CPU overhead). Three additional sweep benchmarks investigate how overhead scales with the **volume of data written per event**, the **event generation rate**, and the **number of entries in a BPF map**.

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
sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py
sudo python3 tests/bench_event_rate_sweep/bench_event_rate_sweep.py
sudo python3 tests/bench_map_size_sweep/bench_map_size_sweep.py
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

## Data Volume & Rate Sweep Benchmarks

These three benchmarks extend the suite to investigate how overhead **scales with the amount of data written per event** and with the **event generation rate**.

---

### `bench_payload_sweep` — Payload Size vs. Latency

**What it measures:** For `BPF_PERF_OUTPUT` and `BPF_RINGBUF`, how per-event kernel→userspace latency and throughput change as the event payload grows from 8 B to 4096 B.

**How to run:**
```bash
sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py
sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py --events 5000
sudo python3 tests/bench_payload_sweep/bench_payload_sweep.py \
    --sizes 8,64,512,4096 --output-dir /tmp/results
```

**Payload sizes swept (bytes):** `8, 32, 64, 128, 256, 512, 1024, 2048, 4096`

**How to interpret results:**
- `mean_ns` and `p99_ns` will increase with `payload_bytes` because larger structs require copying more data through the BPF-to-userspace path.
- An **inflection point** where latency growth accelerates (typically at 512–1024 bytes) corresponds to cache-line boundary effects: small payloads fit in a few cache lines, while larger payloads spill across cache lines and incur more memory traffic.
- `BPF_RINGBUF` is typically faster than `BPF_PERF_OUTPUT` at the same payload size, because its zero-copy design reserves space directly in the shared ring buffer rather than copying into per-CPU perf buffers.
- `events_per_sec` will decrease as `payload_bytes` increases — this is the bandwidth cost made visible.

---

### `bench_event_rate_sweep` — Event Rate vs. Drop Rate & Latency

**What it measures:** With a fixed 256-byte payload, how overhead (latency, drop rate) scales as the event generation rate is pushed from low (1,000 ev/s) to saturating (500,000 ev/s).

**How to run:**
```bash
sudo python3 tests/bench_event_rate_sweep/bench_event_rate_sweep.py
sudo python3 tests/bench_event_rate_sweep/bench_event_rate_sweep.py --window 5
sudo python3 tests/bench_event_rate_sweep/bench_event_rate_sweep.py \
    --rates 1000,10000,100000,500000 --output-dir /tmp/results
```

**Rate steps (events/sec):** `1000, 5000, 10000, 50000, 100000, 250000, 500000`

**How to interpret results:**
- At low rates, `drop_rate_pct` should be near 0 and `mean_ns` should match the baseline latency from `bench_perf_output`.
- The **saturation point** is where `drop_rate_pct` starts rising steeply — this is the rate at which the Python polling loop can no longer keep pace with the kernel-side event submission rate.
- `mean_ns` and `p99_ns` increase near the saturation point due to ring-buffer back-pressure: events wait in the buffer longer before the consumer drains them.
- `BPF_RINGBUF` typically saturates at a higher rate than `BPF_PERF_OUTPUT` because its single shared buffer avoids per-CPU memory fragmentation.
- For production use, keep the target rate well below the saturation point to maintain low `drop_rate_pct` and stable `p99_ns`.

---

### `bench_map_size_sweep` — Map Entry Count vs. Read Latency

**What it measures:** For `BPF_HASH` and `BPF_ARRAY`, how the userspace map-read latency scales with the number of entries in the map (from 100 to 100,000 entries).

**How to run:**
```bash
sudo python3 tests/bench_map_size_sweep/bench_map_size_sweep.py
sudo python3 tests/bench_map_size_sweep/bench_map_size_sweep.py --iterations 200
sudo python3 tests/bench_map_size_sweep/bench_map_size_sweep.py \
    --sizes 100,1000,10000,100000 --output-dir /tmp/results
```

**Map entry counts swept:** `100, 500, 1000, 5000, 10000, 50000, 100000`

**How to interpret results:**
- `mean_iter_us` scales roughly **linearly** with `map_entries` for both map types, since each entry requires at least one `bpf()` syscall round-trip.
- `BPF_ARRAY` is generally faster than `BPF_HASH` at the same entry count because array lookup uses a single `bpf(BPF_MAP_LOOKUP_ELEM)` call, while hash-map iteration requires `bpf(BPF_MAP_GET_NEXT_KEY)` + `bpf(BPF_MAP_LOOKUP_ELEM)` per entry.
- A **cache-effect cliff** may appear around 5,000–50,000 entries where the map data no longer fits in the CPU's L3 cache, causing `mean_iter_us` to grow faster than linearly and `bytes_per_us` to drop noticeably.
- `bytes_per_us` (effective read bandwidth in MB/s) provides a hardware-normalised view of efficiency. A declining trend with growing `map_entries` indicates that the per-entry syscall overhead is being amortised less efficiently.
- No kernel eBPF program is loaded; maps are created and read entirely from userspace, isolating the userspace map-read cost from kernel-side write overhead.

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
├── bench_trace_printk/
│   ├── bench_trace_printk.py
│   └── expected_output.txt
│
├── bench_payload_sweep/
│   ├── bench_payload_sweep.py
│   └── expected_output.txt
│
├── bench_event_rate_sweep/
│   ├── bench_event_rate_sweep.py
│   └── expected_output.txt
│
└── bench_map_size_sweep/
    ├── bench_map_size_sweep.py
    └── expected_output.txt
```

Results are written to `tests/results/` (created automatically):

- `<benchmark_name>.jsonl` — append-only JSON-lines log for trend analysis
- `summary_<timestamp>.json` — combined run summary from `run_all.py`
