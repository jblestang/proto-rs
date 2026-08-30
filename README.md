# proto-rs

[![CI](https://github.com/jblestang/proto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jblestang/proto-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/proto-rs-dynamic.svg)](https://crates.io/crates/proto-rs-dynamic)
[![Documentation](https://docs.rs/proto-rs-dynamic/badge.svg)](https://docs.rs/proto-rs-dynamic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **Development disclosure:** This project has been vibe-coded with OpenAI
> Codex. Users and contributors should review and validate the implementation
> for their own requirements, especially before security-critical use.

A `no_std` + `alloc` Protocol Buffers schema parser and dynamic wire codec. It
does not require generated Rust types: messages are represented by generic
`Message` and `Value` values at runtime.

## Features

- Proto2 and proto3 syntax declarations
- Packages, nested messages, enums, oneofs, repeated and packed fields
- Dynamic maps with protobuf defaults and last-key-wins semantics
- Transitive normal, public, and weak import resolution from in-memory sources
- Syntax and semantic validation of identifiers, declarations, namespaces,
  field tags, reservations, enum aliases, options, and import visibility
- Every scalar protobuf wire type and embedded messages
- Unknown-field preservation across decode/encode
- Field-number and malformed-wire validation
- Checked-in Pest grammar for complete syntax validation
- Unconditional `#![no_std]`; Pest dependencies have their `std` features off

The library has no `std` feature and its Cargo default-feature set is empty.
Its runtime data model uses `core` and `alloc`, and both Pest dependencies are
built with `default-features = false`. Pest generates the parser for the
checked-in `src/proto.pest` grammar when this crate is compiled. User `.proto`
files are always parsed into dynamic descriptors at runtime: they never
generate Rust source, structs, or message-specific codecs. The conformance
adapter under `examples/` is a host-side executable and is not part of the
`no_std` library target.

## Usage

The crates.io package is named `proto-rs-dynamic`; its Rust library name stays
`proto_rs` so imports remain short and compatible with the repository name:

```toml
[dependencies]
proto-rs-dynamic = "0.1"
```

```rust
use proto_rs::{decode, encode, parse, Message, Value};

let schema = parse(r#"
  syntax = "proto3";
  message Greeting { string text = 1; }
"#)?;
let greeting = schema.message("Greeting").unwrap();

let mut message = Message::new();
message.insert("text", Value::String("hello".into()));

let bytes = encode(&schema, greeting, &message)?;
assert_eq!(decode(&schema, greeting, &bytes)?, message);
# Ok::<(), proto_rs::Error>(())
```

For imports, register every source with `Registry::register` and then call
`Registry::parse(root_path)`. The registry owns all schema text before parsing,
so import resolution requires neither filesystem nor standard-library access.
Services and custom options are skipped because they do not affect message
wire encoding.

Decoded messages contain an occurrence-level audit trail. `AuditTag` identifies
schema fields, unknown fields, unknown length-delimited messages, application
additions, last-wins duplicates, and merged message duplicates. Use
`encode_with_options` to independently drop unknown fields, unknown messages,
application-added raw fields, or displaced duplicate occurrences.

The runnable audit example receives a message with a duplicated singular field,
an unknown scalar field, and an unknown length-delimited field. It prints the
occurrence-level evidence and serializes a sanitized message containing only
the expected last-wins values. It also selects `FieldOrder::FieldNumber`, which
stably orders every emitted occurrence by numeric protobuf field ID:

```bash
cargo run --example filter_spurious_fields
```

See [`examples/filter_spurious_fields.rs`](examples/filter_spurious_fields.rs)
for the complete dynamic, generated-code-free workflow.

## Wire sanitization

`decode_with_options` provides explicit limits for message bytes, recursion,
field occurrences, length-delimited values, repeated values, map entries, and
retained audit bytes. Policies can drop or reject unknown fields, reject
duplicate singular fields and map keys, require minimal varints, retain only
audit metadata, reject noncanonical booleans, and reject unknown enum values.

`encode_with_options` can order fields numerically, sort map entries by key,
normalize NaN and signed-zero representations, filter schema-external data,
and reject output above a configured byte budget. These controls improve
repeatability but do not claim canonical protobuf serialization.

See [SANITIZATION.md](SANITIZATION.md) for the complete list of unconditional
checks, opt-in policies, recommended usage, test coverage, and pending work.

## Official conformance test suite

The `examples/conformance_testee.rs` adapter runs this crate against Google's
official Protocol Buffers conformance test suite without generated Rust message
code. Against protobuf v34.1, the strict (`--enforce_recommended`) run reports:

```text
1400 successes, 1406 skipped, 0 expected failures, 0 unexpected failures
```

This covers full proto3 binary behavior and basic proto2 binary behavior.
JSON, text format, Editions, proto2 groups/extensions, and MessageSet are the
only intentionally ignored or excluded capabilities.
[CONFORMANCE.md](CONFORMANCE.md) explains exactly which tests pass, which are
explicitly skipped, which are not scheduled, and what the suite does not
prove. GitHub CI rebuilds the official runner from the commit in
`conformance/VERSION` and requires the conformance test suite to pass on every
pull request and push to `main`. Run it locally with:

```bash
bash conformance/run.sh
```

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo check --lib --no-default-features
```

Run the single-threaded strict sanitization throughput benchmark with:

```bash
cargo bench --bench strict_throughput
```

The benchmark excludes schema parsing and reports strict decode, strict encode,
and combined decode/encode throughput for a small dynamic packet.
See [BENCHMARKS.md](BENCHMARKS.md) for the recorded environment, methodology,
results, throughput estimate, and interpretation limits.

The decoder also has a coverage-guided `cargo-fuzz` target for compatibility
and strict-policy paths. Setup and bounded-run commands are documented in
the repository's
[fuzzing guide](https://github.com/jblestang/proto-rs/blob/main/fuzz/README.md).

## License

The crate is licensed under the [MIT License](LICENSE). Files vendored from the
official Protocol Buffers conformance test suite retain their upstream license;
see `conformance/upstream/LICENSE` in the repository.
