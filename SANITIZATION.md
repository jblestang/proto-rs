# Wire sanitization

This document describes the validation, sanitization, normalization, and
resource controls applied by `proto_rs` to Protocol Buffers binary messages.
It also records limitations that are not yet implemented or cannot be solved
generically without application knowledge.

## Security boundary

`decode` and `encode` use protobuf-compatible defaults. Those defaults are
intended for interoperability: unknown fields are preserved, duplicates use
protobuf merge or last-wins behavior, alternate valid varint representations
are accepted, and complete audit bytes are retained. The default decoder has a
recursion limit of 100, but its other resource budgets are effectively
unbounded.

Applications receiving untrusted data should use `decode_with_options` and
choose finite limits appropriate to their protocol. Applications producing a
sanitized output should use `encode_with_options`.

Successful decoding means that the message passed all configured wire rules.
It does not mean that the sender is authorized or that field values satisfy
application-specific business rules.

## Always enforced

The following checks apply to both compatibility and strict decoding:

- Truncated keys, varints, fixed-width fields, and length-delimited values are
  rejected.
- Varints longer than ten bytes and overflowing tenth bytes are rejected.
- Field keys wider than five bytes are rejected.
- Field number zero and numbers above 536,870,911 are rejected.
- Unknown groups are recursively skipped only when their end tag matches the
  opening field number; truncated, mismatched, and standalone end-group tags
  are rejected.
- A schema-known field with the wrong wire type is rejected.
- Every descriptor-known string is checked for valid UTF-8.
- Length arithmetic uses checked addition before slicing.
- Wire lengths are converted from `u64` to `usize` with checked conversion.
  This prevents truncation on 32-bit targets.
- Packed fixed-width fields must end on a complete value boundary.
- Map entries cannot read beyond their declared length.
- Missing proto2 required fields are rejected after decoding.
- Missing proto2 required fields are rejected before encoding.
- Dynamic values incompatible with their field descriptors are rejected by the
  encoder.
- Invalid numeric field IDs and wire types on application-added raw fields are
  rejected by the encoder.
- Public codec APIs return `Result`; malformed input is covered by explicit
  no-panic tests.

## Configurable decode sanitization

`DecodeOptions` controls resource consumption and strict input acceptance.

### Message and allocation-related limits

- `max_message_bytes` limits the root and every embedded message.
- `max_recursion_depth` limits nested message edges below the root. A value of
  zero permits the root message but no embedded messages.
- `max_field_occurrences` limits the total number of wire occurrences across
  the root, embedded messages, and synthetic map-entry fields.
- `max_length_delimited_bytes` limits each string, bytes value, embedded
  message, packed field, and map entry.
- `max_repeated_values` limits the retained values in each repeated field. It
  applies across packed and unpacked occurrences.
- `max_map_entries` limits the distinct keys retained in each map field.
- Every internal counter uses checked arithmetic.

These are independent limits. A gateway should normally set all of them rather
than relying on one total-message limit.

### Unknown fields

`UnknownFieldPolicy` has three modes:

- `Preserve` retains unknown values for forward-compatible reserialization.
- `Drop` removes unknown values from the dynamic message but retains their audit
  records.
- `Reject` fails decoding when the first unknown field number is encountered.

Unknown length-delimited values receive `AuditTag::UnknownMessage`, meaning
they may be an embedded message. The wire format does not reveal whether such
a value is actually a message, bytes, text, or packed scalar data.

### Duplicate and oneof handling

`DuplicateInputPolicy::Allow` implements normal protobuf behavior:

- Singular scalar, string, bytes, and enum fields use the last value.
- Singular embedded messages merge recursively.
- Repeated values append in encounter order.
- Different oneof members displace the previously selected member.
- Duplicate map keys retain the last value.

Every displaced, retained, or merged occurrence is tagged in the audit trail.
If three or more singular values occur, every previous winner is correctly
demoted to `DuplicateDiscarded`.

`DuplicateInputPolicy::Reject` rejects:

- Duplicate singular fields.
- Conflicting oneof members.
- Duplicate map keys across entries.
- Duplicate key or value members inside one synthetic map entry.

Repeated fields are intentionally not treated as duplicates.

### Minimal and width-correct varints

When `require_minimal_varints` is enabled:

- Field keys must use the shortest varint representation.
- Length prefixes must use the shortest representation.
- Scalar varints must use the shortest representation.
- `int32` and enum values must round-trip without lossy 64-to-32-bit
  truncation. Negative `int32` and enum values therefore require their proper
  ten-byte representation.
- `uint32` and `sint32` values above their 32-bit encoded width are rejected
  instead of being truncated.
- Unknown varint fields and unknown length prefixes are checked too.

Compatibility decoding continues accepting protobuf's permissive alternate
representations and normalizes known fields when they are re-encoded.

### Boolean and enum domains

`BooleanValuePolicy::CoerceNonzero` implements normal protobuf behavior: zero
is false and every nonzero value is true.

`BooleanValuePolicy::RejectNonCanonical` accepts only numeric zero and one.

`EnumValuePolicy::Preserve` retains any signed 32-bit enum number, including
numbers absent from the descriptor. This is normal proto3 open-enum behavior.

`EnumValuePolicy::RejectUnknown` accepts only numbers declared by the resolved
enum descriptor. This is an application sanitization policy and can be used
when a gateway requires a closed set of values.

### Audit retention

Every decoded message-level field occurrence produces an `AuditRecord`
containing its tag, field name when known, field number, and wire type. Packed
elements and synthetic members inside one map entry share their containing
field's record.

`AuditMode::Full` also copies the complete original field bytes. The cumulative
copy volume is limited by `max_audit_bytes`. Nested data may be represented in
both a containing field record and nested records, so this limit should be
smaller than the application's total memory budget.

`AuditMode::MetadataOnly` retains metadata without copying original occurrence
bytes. It is suitable when evidence of unknown or duplicate data is required
but exact replay is not.

`DuplicatePolicy::PreserveAll` cannot replay displaced occurrences from a
metadata-only audit. Encoding returns an error instead of silently claiming to
have preserved unavailable bytes.

## Configurable encode sanitization

`EncodeOptions` controls what data is forwarded and how retained values are
normalized.

### Schema-external data

- `forward_unknown_fields` controls unknown scalar and fixed-width fields.
- `forward_unknown_messages` controls unknown length-delimited fields.
- `forward_added_fields` controls application-added raw fields.
- A schema-absent named value without raw wire metadata cannot be forwarded and
  produces an error.

Setting all three forwarding options to false produces output containing only
descriptor-known values.

### Duplicate output

- `DuplicatePolicy::LastOnly` emits only the semantic value retained by decode.
- `DuplicatePolicy::PreserveAll` replays displaced original occurrences before
  the retained value when complete audit bytes are available.

For sanitization, `LastOnly` is normally the appropriate policy.

### Ordering

- `FieldOrder::Declaration` emits known fields in descriptor declaration order,
  followed by forwarded external data.
- `FieldOrder::FieldNumber` stably sorts all emitted known, unknown, added, and
  preserved duplicate occurrences by numeric field ID. Equal-number
  occurrences retain their relative order.
- `MapOrder::Preserve` retains dynamic map insertion order.
- `MapOrder::Key` sorts all protobuf-supported signed, unsigned, boolean, and
  string map keys while keeping values attached to their keys.

Ordering improves repeatability within this implementation. It does not make
protobuf serialization universally canonical.

### Floating-point normalization

`FloatEncoding::Preserve` retains finite values, signed zero, and NaN payload
bits.

`FloatEncoding::Normalize`:

- Converts every 32-bit NaN to one documented quiet-NaN bit pattern.
- Converts every 64-bit NaN to one documented quiet-NaN bit pattern.
- Converts negative zero to positive zero.
- Leaves finite nonzero values unchanged.

### Output budget

`max_output_bytes` rejects each completed root or embedded serialized message
whose encoded size exceeds the configured budget.

This is a final encoded-size guard. The current encoder builds a message in
memory before checking its final size; it is not a streaming allocation limit.
Applications must also bound programmatically created messages, maps, repeated
values, bytes, and strings.

## Example hardened profile

The correct values depend on the application protocol. This example accepts a
small request, drops unknown data while auditing it, normalizes ambiguous wire
forms, and preserves protobuf last-wins behavior for later inspection:

```rust
use proto_rs::{
    AuditMode, BooleanValuePolicy, DecodeOptions, DuplicateInputPolicy,
    EnumValuePolicy, UnknownFieldPolicy,
};

const KIBIBYTE: usize = 1024;
const MAX_REQUEST_BYTES: usize = 64 * KIBIBYTE;
const MAX_VALUE_BYTES: usize = 16 * KIBIBYTE;

let options = DecodeOptions {
    max_message_bytes: MAX_REQUEST_BYTES,
    max_recursion_depth: 16,
    max_field_occurrences: 1024,
    max_length_delimited_bytes: MAX_VALUE_BYTES,
    max_repeated_values: 256,
    max_map_entries: 256,
    max_audit_bytes: MAX_REQUEST_BYTES,
    unknown_fields: UnknownFieldPolicy::Drop,
    duplicates: DuplicateInputPolicy::Allow,
    audit_mode: AuditMode::Full,
    require_minimal_varints: true,
    booleans: BooleanValuePolicy::RejectNonCanonical,
    enum_values: EnumValuePolicy::RejectUnknown,
};
# let _ = options;
```

The runnable end-to-end example is
[`examples/filter_spurious_fields.rs`](examples/filter_spurious_fields.rs).

## Pending or intentionally unresolved

The following items are not currently implemented:

- Field-specific policies such as per-field string limits, numeric ranges,
  regular-expression checks, enum allowlists, required business fields, or
  cross-field invariants.
- Unknown-field allowlists or denylists by numeric field ID or range. Unknown
  fields can currently be preserved, dropped, or rejected globally.
- Automatic proto2 closed-enum behavior based on the syntax of the file that
  defines the enum. `RejectUnknown` is currently an explicit policy applied to
  every enum.
- Canonicalization of preserved unknown length-delimited values. Their content
  type is unknowable without a descriptor, so generic recursive normalization
  would be unsafe.
- Minimal-varint rewriting for preserved raw unknown or application-added
  fields during encoding. Strict decoding can reject non-minimal received
  unknown fields; otherwise preserved raw values remain byte-exact.
- A single total heap-allocation budget covering dynamic values, descriptor
  lookups, audit metadata, and temporary encoder sorting structures.
- Streaming decode or encode with an allocation budget enforced before every
  write. `max_output_bytes` currently validates completed message buffers.
- Configurable schema-parser limits for source size, declaration count, nesting,
  import graph size, or descriptor allocation. Registry contents should be
  bounded by their loader.
- Cryptographic authentication, authorization, replay prevention, freshness,
  confidentiality, checksums, or signatures. These belong to the transport or
  application protocol.
- Semantic inspection of opaque `bytes` fields that themselves contain a
  serialized protobuf message.
- Declared proto2 groups and extensions, MessageSet, Editions, JSON, and text
  format. Unknown group wire values are supported even though group schema
  declarations are not. Their status is tracked in
  [`CONFORMANCE.md`](CONFORMANCE.md).

Protobuf serialization is not universally canonical. Do not use encoded bytes
as a stable cross-version signature or identity merely because numeric field,
map, and float normalization options were enabled.

## Test coverage

Unit tests explicitly cover:

- Unknown-field preserve, drop, and reject policies.
- Minimal keys, scalar varints, length prefixes, and strict 32-bit widths.
- Message, length-delimited, recursion, occurrence, repeated, and map limits.
- Full audit-byte limits and metadata-only audit behavior.
- Scalar, oneof, map-key, and synthetic map-entry duplicate rejection.
- Correct audit tags across three singular occurrences.
- Boolean and enum strict-value policies.
- Numeric field ordering and map-key ordering.
- NaN and signed-zero normalization.
- Encoded-output size rejection.
- Metadata-only duplicate replay rejection.
- Malformed-input no-panic behavior.
- Coverage-guided compatibility and strict decoder fuzzing through the
  [repository fuzz target](https://github.com/jblestang/proto-rs/blob/main/fuzz/fuzz_targets/decode.rs).
- An always-runnable deterministic 10,000-packet randomized smoke corpus.

The official Protocol Buffers conformance test suite is also run with
compatibility defaults; see [`CONFORMANCE.md`](CONFORMANCE.md) for the pinned
result and intentional exclusions.
