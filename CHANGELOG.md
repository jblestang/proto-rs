# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/jblestang/proto-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jblestang/proto-rs/releases/tag/v0.1.0
