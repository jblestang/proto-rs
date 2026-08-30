# Protocol Buffers conformance test suite

This project is tested with Google's official Protocol Buffers conformance
test suite. The suite checks interoperability by sending framed requests to
[`examples/conformance_testee.rs`](examples/conformance_testee.rs), which
decodes and re-encodes messages through the crate's dynamic API. The adapter
does not use Rust message code generated from `.proto` files.

## Pinned upstream version

The tested protobuf release and exact upstream commit are recorded in
[`conformance/VERSION`](conformance/VERSION). The repository contains only the
upstream sources required by the local runner in `conformance/upstream`.

GitHub CI checks out the complete source tree at that exact commit to build a
matching `protoc` and `conformance_test_runner`. It then runs the suite with
recommended tests enforced:

```bash
bash conformance/run.sh
```

An unexpected failure, adapter error, unknown message type, or malformed
runner request makes the CI conformance job fail. Such cases are not converted
into skips.

## Exercised and passing

The following binary-wire areas are exercised and pass:

- All required and recommended proto3 binary cases scheduled by the pinned
  runner.
- Basic proto2 binary cases for scalars, enums, strings, bytes, embedded
  messages, repeated fields, packed and unpacked values, maps, oneofs, unknown
  fields, and required-field behavior.
- Singular embedded-message merging and scalar or oneof last-value-wins
  behavior.
- Preservation and reserialization of unknown fields using supported wire
  types.

The last verified result is:

```text
Binary/JSON suite: 1400 successes, 1406 skipped, 0 expected failures,
                   0 unexpected failures
Text suite:          0 successes,  434 skipped, 0 expected failures,
                   0 unexpected failures
```

## Ignored or excluded portions

"Ignored" does not mean that arbitrary failures are suppressed. Only the
following known feature families are outside the supported conformance scope.

### Tests scheduled but explicitly skipped by the adapter

- **Protocol Buffers JSON:** JSON payloads and JSON output requests are
  answered with `ConformanceResponse.skipped`. No JSON conformance case is
  claimed as passing.
- **Protocol Buffers text format:** Text payloads and text output requests are
  answered with `ConformanceResponse.skipped`. Consequently, the text suite's
  434 cases are all reported as skipped.
- **Proto2 groups, extensions, and MessageSet:** Binary proto2 cases that need
  an unsupported legacy wire construct are answered as skipped when the codec
  reports the unsupported wire type. Ordinary proto2 binary cases continue to
  run and pass.
- **JSPB:** JSPB payload or output requests are answered as skipped. JSPB is an
  optional upstream format and is not part of the claimed binary coverage.

### Tests not scheduled as supported coverage

- **Editions 2023 and unstable Editions:** The runner is not given a maximum
  Editions level, because Editions syntax and feature resolution are not
  implemented. If an Editions request is nevertheless received, the adapter
  answers it as skipped.

No failure list is passed to the runner, and the project does not maintain a
list of expected failures. The only accepted non-success result is an explicit
skip belonging to one of the feature families above.

## What this suite does not prove

The official Protocol Buffers conformance test suite primarily validates
protobuf serialization and parsing behavior. It does not provide complete
coverage for this crate's:

- `.proto` syntax and semantic validation;
- registry import resolution and import visibility;
- strict sanitization policies and resource limits;
- audit tags and filtering policies;
- no-panic behavior under arbitrary malformed input; or
- `no_std` compilation.

Those properties are covered separately by unit tests, doctests, fuzzing,
strict Clippy and rustdoc checks, and the alloc-only CI build. See
[`SANITIZATION.md`](SANITIZATION.md) for the sanitization-specific coverage and
remaining limitations.

## CI enforcement

The `Official pinned protobuf conformance` job in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every pull
request and every push to `main`. The job builds the upstream tools and their
pinned dependencies from source, builds the Rust adapter, and requires both
the binary/JSON and text conformance suites to exit successfully.
