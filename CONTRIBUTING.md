# Contributing

Thank you for improving `proto-rs`. Please open an issue before a large API or
wire-semantics change so its scope can be agreed before implementation.

## Local checks

Changes must preserve the crate's unconditional `no_std` + `alloc` design and
must not generate Rust message code from `.proto` files. Before opening a pull
request, run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo check --lib --no-default-features
RUSTDOCFLAGS=-Dwarnings cargo doc --lib --no-deps --no-default-features
cargo check --manifest-path fuzz/Cargo.toml --bin decode
```

Wire behavior and sanitization changes need focused unit tests. Schema parser
changes need both syntax and semantic validation tests. User-visible changes
belong under `Unreleased` in `CHANGELOG.md`.

Run `bash conformance/run.sh` when changing protobuf compatibility. The
official Protocol Buffers conformance test suite requires host tools and is
intentionally separate from the `no_std` library. See `CONFORMANCE.md` for the
passing, explicitly skipped, and excluded areas.

## Pull requests

Keep commits focused, document public APIs, and explain any compatibility or
resource-usage impact. By submitting a contribution, you agree that it is
licensed under the repository's MIT License.
