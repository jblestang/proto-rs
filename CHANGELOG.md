# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-08-31

### Added

- Added Edition 2023 parsing, inherited standard feature resolution, and
  descriptor-driven binary semantics.
- Added protobuf JSON parsing and serialization, including well-known types,
  strict numeric handling, duplicate-key detection, maps, extensions, and
  unknown-enum behavior.
- Added typed proto2 and Edition extension declarations, extension ranges,
  Registry resolution, semantic collision checks, and dynamic wire handling.
- Completed proto3 service and RPC descriptors, built-in and custom option
  retention and validation, JSON-name collision checks, and cross-file custom
  option resolution.
- Added safe recursive preservation of unknown wire groups, moving 14 official
  conformance cases from skipped to passing.

### Changed

- Enabled Edition 2023 and protobuf JSON in the official conformance suite;
  5,623 binary/JSON cases pass with four intentional JSPB skips and no
  failures.
- Registry parsing now rejects import cycles and proto3 references to proto2
  enums, and resolves declarations before validating imported option uses.

### Documentation

- Added a precise conformance test suite statement covering passing cases,
  intentional skips, excluded areas, and CI enforcement.
- Added automatic crates.io publication from version-matched GitHub Releases
  using short-lived OIDC trusted-publishing credentials.

## [0.1.0] - 2026-08-30

### Added

- `no_std` and `alloc`-only dynamic Protocol Buffers schema parsing.
- Full proto3 binary and basic proto2 binary wire support without generated
  message code.
- In-memory registry-based import resolution and semantic schema validation.
- Auditable decoding, configurable wire sanitization, deterministic encoding,
  resource limits, and unknown-field filtering.
- Official protobuf conformance harness, unit tests, benchmarks, and a
  coverage-guided decoder fuzz target.

[Unreleased]: https://github.com/jblestang/proto-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jblestang/proto-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jblestang/proto-rs/releases/tag/v0.1.0
