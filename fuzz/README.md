# Decoder fuzzing

The `decode` target uses `cargo-fuzz` and LLVM libFuzzer to exercise both the
compatibility decoder and policy-varying strict decoder. Successful messages
are sanitized and re-encoded to cover recursive decode/encode interactions.

Install the official cargo subcommand, then run from the repository root:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run decode -- -max_len=4098 -timeout=5 -dict=fuzz/protobuf.dict
```

For a bounded smoke run suitable for a developer workstation:

```bash
cargo +nightly fuzz run decode -- -runs=100000 -max_len=4098 -timeout=5 \
  -dict=fuzz/protobuf.dict
```

The first two fuzz bytes select the descriptor, sanitization policies, and
resource limits. The remaining bytes are passed to the decoder, capped at 4096
bytes. Crashes and timeouts are written under `fuzz/artifacts`, which is ignored
by Git. Minimized regression inputs should be copied into a normal unit test
before closing the defect.

The fuzz package is isolated from the main Cargo package. `libfuzzer-sys` is a
host-only fuzzing dependency and does not affect the library's unconditional
`no_std` build or its dependency feature set.

The normal unit suite also executes 10,000 deterministic randomized packets
through compatibility decode, strict decode, and successful re-encoding. That
test provides an always-runnable smoke corpus when a sanitizer runtime is not
available; it does not replace libFuzzer's coverage guidance.
