# Performance benchmarks

This document records reproducible local measurements for the dynamic binary
codec. Results are estimates for comparing changes and establishing an initial
single-core capacity envelope. They are not portable guarantees.

## Strict small-packet benchmark

Run the benchmark with:

```bash
cargo bench --bench strict_throughput
```

The benchmark implementation is
[`benches/strict_throughput.rs`](benches/strict_throughput.rs).

### Workload

- One 28-byte proto3 binary packet.
- Five known fields: `uint32`, `float`, a two-entry `map<uint32, uint32>`, a
  four-byte string, and a boolean.
- Runtime schema and dynamic `Message` values; no generated protobuf code.
- Schema parsing and descriptor lookup setup occur before timing.
- 20,000 warm-up iterations before each measurement.
- 1,000,000 timed iterations per operation.
- Single-threaded execution under Cargo's optimized `bench` profile.
- Results are consumed through `std::hint::black_box`.
- Dynamic value and audit allocations are included.

Strict decoding enables:

- Finite message, depth, occurrence, length, repeated, map, and audit limits.
- Unknown-field rejection.
- Duplicate singular, oneof, and map-key rejection.
- Full occurrence-byte auditing.
- Minimal and width-correct varints.
- Canonical boolean validation.
- Declared-only enum validation.

Strict encoding enables:

- Unknown and application-added field removal.
- Last-only duplicate serialization.
- Numeric field ordering.
- Map-key ordering.
- NaN and signed-zero normalization.
- A finite output-size budget.

### Measurement environment

- Date: 2026-08-30.
- Hardware: Apple M2 MacBook Air, 8 CPU cores, 16 GB memory.
- Architecture: `aarch64-apple-darwin`.
- Rust: 1.92.0.
- LLVM: 21.1.3.
- Operating system kernel: Darwin 25.5.0.

### Four-run result

Strict decode:

- Range: 932,777 to 938,787 messages/second.
- Average: approximately 935,600 messages/second.
- Average latency: approximately 1,069 ns/message.
- Logical payload rate: approximately 25.0 MiB/second.

Strict encode of a pre-built dynamic message:

- Range: 1,480,111 to 1,551,807 messages/second.
- Average: approximately 1,517,200 messages/second.
- Average latency: approximately 659 ns/message.
- Logical payload rate: approximately 40.5 MiB/second.

Strict decode followed by encoding the decoded and audited message:

- Range: 475,164 to 482,099 messages/second.
- Average: approximately 478,400 messages/second.
- Average latency: approximately 2,090 ns/message.
- Logical payload rate: approximately 12.8 MiB/second.

The combined measurement is intentionally slower than adding the isolated
decode and pre-built-message encode timings. Encoding a decoded message also
clones its populated audit trail, which reflects the sanitizer gateway path.

### Throughput estimate

For this exact packet and strict profile, a reasonable hot-cache single-core
estimate is:

- About 0.93 million strict decodes per second.
- About 1.48 million strict encodes per second using the conservative observed
  lower bound.
- About 0.475 million complete decode/sanitize/encode operations per second
  using the conservative observed lower bound.
- The best observed complete-path run was approximately 0.482 million
  messages/second.

An arithmetic four-performance-core ceiling would be about 1.9 million
complete operations per second, but that number was not measured. Allocator
contention, cache pressure, scheduling, mixed performance/efficiency cores,
and application work will prevent reliably linear scaling. Capacity planning
should use a future multithreaded benchmark on the deployment hardware.

### Interpretation limits

- MiB/second is calculated from the 28-byte logical packet size. It is not a
  measurement of total memory traffic or allocator bandwidth.
- Transport framing, network I/O, schema registration, schema parsing,
  descriptor selection, logging, authorization, and application validation are
  excluded.
- The complete packet is resident in memory and hot in cache.
- Larger strings, nested messages, maps, repeated values, unknown fields, and
  audit payloads will change both allocation cost and throughput.
- `no_std` targets may use different allocators and substantially different
  processors.
- Cargo's benchmark profile is optimized but is not tuned for a particular
  deployment CPU.
- Protobuf performance is workload-sensitive; this result should not be
  extrapolated by byte size alone.

## Regression use

Run several repetitions after codec changes and compare ranges rather than a
single result. The benchmark intentionally has no external benchmarking
dependency, keeping the library's dependency and `no_std` policy unchanged.

For stable CI regression detection, a future harness should record distributions,
pin CPU affinity where supported, suppress frequency scaling, and compare
statistically significant changes on dedicated hardware.
