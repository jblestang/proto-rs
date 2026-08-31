//! Dynamic Protocol Buffers wire codec.
//!
//! # Design boundaries
//!
//! The codec operates on descriptors produced by the schema module.
//! It never relies on generated Rust structs or generated field accessors.
//! Values are stored in an allocation-backed runtime representation.
//! All byte processing uses `core` and `alloc` only.
//! No stream, file, socket, clock, or operating-system API is required.
//! The caller owns framing and transport concerns.
//! The caller also chooses which descriptor describes each payload.
//!
//! # Wire keys
//!
//! Every protobuf occurrence starts with an unsigned varint key.
//! The upper bits contain the positive field number.
//! The lower three bits contain the wire type.
//! Field number zero is always rejected.
//! Field numbers above 536,870,911 are always rejected.
//! Tags that need more than five bytes are rejected.
//! This prevents a wide integer from truncating into a plausible field tag.
//! Reserved schema field numbers are rejected by the schema parser.
//!
//! # Wire types
//!
//! Wire type zero carries varints.
//! It represents signed integers, unsigned integers, booleans, and enums.
//! Negative `int32` and `int64` values use ten-byte two's-complement varints.
//! `sint32` and `sint64` use zig-zag transformation before varint encoding.
//! Wire type one carries fixed-width little-endian 64-bit values.
//! It represents `fixed64`, `sfixed64`, and `double`.
//! Wire type two carries a varint length followed by bytes.
//! It represents strings, bytes, messages, packed fields, and map entries.
//! Wire type five carries fixed-width little-endian 32-bit values.
//! It represents `fixed32`, `sfixed32`, and `float`.
//! Wire types three and four carry unknown groups and Edition `DELIMITED`
//! message fields; matching terminators and nesting are validated.
//! A decoder never guesses a different type after a wire-type mismatch.
//!
//! # Dynamic values
//!
//! [`Value`] mirrors the protobuf scalar type families.
//! Signed fixed and zig-zag values share the signed integer variants.
//! Unsigned and fixed unsigned values share the unsigned variants.
//! Enums retain their numeric value, including unknown enum numbers.
//! Strings normally validate UTF-8; Edition fields selecting validation `NONE`
//! use [`Value::RawString`] to preserve arbitrary payload bytes losslessly.
//! Embedded messages recursively contain another [`Message`].
//! Repeated values retain encounter order.
//! Maps retain deterministic insertion order in a vector.
//! Map duplicate keys are replaced using last-key-wins semantics.
//! The dynamic representation does not borrow from the input payload.
//! A successfully decoded message therefore owns all of its data.
//!
//! # Singular field semantics
//!
//! Repeating a singular scalar field applies protobuf's last-wins rule.
//! Repeating a singular string or bytes field also applies last-wins.
//! Repeating a singular enum applies last-wins without rejecting unknown values.
//! Repeating the same oneof member applies its normal scalar or message rule.
//! Encountering a different oneof member removes the previously selected one.
//! Singular embedded-message occurrences are merged instead of replaced.
//! Recursive singular messages merge recursively.
//! Repeated fields inside merged messages are concatenated.
//! Maps inside merged messages apply last-key-wins for each key.
//! Unknown fields inside merged messages are appended to the audit data.
//! These rules match the official Protocol Buffers conformance test suite.
//!
//! # Repeated and packed fields
//!
//! A decoder accepts packed and unpacked encodings for packable primitives.
//! Multiple packed segments append values rather than replacing them.
//! Packed lengths are checked with overflow-safe arithmetic.
//! Fixed-width packed segments must contain complete values.
//! A truncated packed value is reported as a parse error.
//! Proto3 packable fields serialize packed unless explicitly disabled.
//! Proto2 packable fields serialize unpacked unless explicitly enabled.
//! Empty repeated fields produce no wire occurrence.
//! Strings, bytes, messages, and maps are never packed.
//!
//! # Maps
//!
//! Maps use protobuf's synthetic entry-message wire representation.
//! Entry field one is the key.
//! Entry field two is the value.
//! Missing keys receive the scalar key type's protobuf default.
//! Missing values receive the value type's protobuf default.
//! Unknown entry fields are skipped within the entry boundary.
//! Entry decoding may not read beyond its declared length.
//! Duplicate keys retain the last decoded value.
//! The audit trail still identifies that a duplicate key occurred.
//! Valid map keys are enforced by the schema parser.
//! Nested maps are rejected by the schema parser and default-value logic.
//!
//! # Unknown data
//!
//! Unknown values preserve their original encoded value bytes.
//! Their stored bytes exclude the key because number and wire type are explicit.
//! Encoding reconstructs the key and appends the untouched value bytes.
//! This makes ordinary decode/encode cycles forward-compatible.
//! Unknown varints retain non-canonical but valid encodings.
//! Unknown fixed-width values retain their exact bit patterns.
//! Unknown length-delimited values retain their exact length and payload bytes.
//! An unknown length-delimited value may represent a future nested message.
//! For that reason its audit tag is [`AuditTag::UnknownMessage`].
//! Other unknown wire occurrences use [`AuditTag::UnknownField`].
//! Encoding options can filter these two categories independently.
//!
//! # Application-added fields
//!
//! A field absent from the descriptor cannot be encoded from a name alone.
//! Its field number, wire type, and encoded value are not inferable.
//! [`AddedField`] supplies that missing wire metadata explicitly.
//! [`Message::add_field`] records the addition in the audit trail.
//! Added values are raw by design and do not pretend to be schema-validated.
//! Invalid field numbers and invalid wire types are rejected during encoding.
//! Named values inserted directly into `Message::fields` are also detected.
//! Such name-only additions can be dropped and audited.
//! Forwarding a name-only addition returns an actionable encoding error.
//! Callers that need forwarding should use [`Message::add_field`].
//!
//! # Audit trail
//!
//! [`AuditRecord`] describes every decoded wire occurrence.
//! It stores the source tag, optional schema name, number, and wire type.
//! It also stores the complete original field bytes including the key.
//! [`AuditTag::SchemaField`] identifies a normal descriptor-known occurrence.
//! [`AuditTag::UnknownField`] identifies unknown non-length-delimited data.
//! [`AuditTag::UnknownMessage`] identifies unknown length-delimited data.
//! [`AuditTag::AddedField`] identifies application-supplied raw data.
//! [`AuditTag::DuplicateDiscarded`] identifies a displaced earlier value.
//! [`AuditTag::DuplicateLastWins`] identifies the later retained value.
//! [`AuditTag::DuplicateMerged`] identifies a merged message occurrence.
//! Audit records are metadata and do not affect semantic message equality.
//! Encoding returns the relevant records through [`EncodeOutput`].
//! Applications can persist, inspect, count, or reject records by tag.
//!
//! # Forwarding policy
//!
//! [`EncodeOptions`] makes forwarding decisions explicit and local.
//! `forward_unknown_fields` governs unknown scalar and fixed-width data.
//! `forward_unknown_messages` governs unknown length-delimited data.
//! `forward_added_fields` governs application-added raw fields.
//! [`DuplicatePolicy::LastOnly`] emits only the retained singular value.
//! [`DuplicatePolicy::PreserveAll`] re-emits displaced raw occurrences.
//! [`FieldOrder::Declaration`] follows descriptor declaration order.
//! [`FieldOrder::FieldNumber`] stably orders all emitted wire occurrences.
//! [`MapOrder::Key`] provides stable protobuf-key ordering within maps.
//! [`FloatEncoding::Normalize`] removes NaN-payload and signed-zero variance.
//! `max_output_bytes` rejects an encoded root or embedded message above budget.
//! The ordinary [`encode`] function uses conservative compatibility defaults.
//! Those defaults forward unknown and added raw fields.
//! Those defaults emit only the last singular scalar occurrence.
//! Nested-message encoding receives the same options as its parent.
//! Filtering never mutates the in-memory message or its audit trail.
//!
//! # Proto3 presence
//!
//! Implicit-presence proto3 scalar defaults are omitted during serialization.
//! This includes zero numbers, false, empty strings, empty bytes, and enum zero.
//! Explicit `optional` fields retain presence even when holding a default value.
//! Oneof members retain presence even when holding a default value.
//! Message fields always have explicit presence.
//! Proto2 optional and required fields always have explicit presence.
//! Presence metadata is computed after user-defined type resolution.
//! This avoids mistaking an unresolved enum name for a message field.
//!
//! # Parse errors and limits
//!
//! Every read checks the available input before slicing.
//! Every length addition uses checked arithmetic where overflow is possible.
//! Varints longer than ten bytes are rejected.
//! A tenth varint byte may contain at most the low bit.
//! Strings with invalid UTF-8 are rejected.
//! Known fields with incompatible wire types are rejected.
//! Unknown group wire types are rejected rather than partially consumed.
//! Required proto2 fields are checked after the complete message is decoded.
//! Required fields are also checked before encoding.
//! Errors carry the byte offset at which the problem became observable.
//! [`DecodeOptions`] bounds size, depth, occurrences, collections, and auditing.
//! It can reject non-minimal varints, ambiguous duplicates, unknown fields,
//! noncanonical boolean values, and enum values absent from the descriptor.
//! Every wire length is checked before conversion to the target's `usize`.
//! [`decode`] uses compatibility policies and a conventional depth limit.
//! Security boundaries should use [`decode_with_options`] with local budgets.
//!
//! # Sanitizing untrusted input
//!
//! Wire validity and application acceptance are deliberately separate layers.
//! [`decode`] accepts protobuf-compatible alternate representations.
//! It preserves unknown data so old and new schema versions can interoperate.
//! That behavior is appropriate for ordinary message forwarding.
//! A trust boundary can instead call [`decode_with_options`].
//! Each strict policy is independent and can be adopted incrementally.
//! Limits are checked before retaining the affected value or audit bytes.
//! An error never returns a partially decoded public [`Message`].
//! The caller can therefore treat success as acceptance by every chosen rule.
//! Sanitization still cannot replace domain-specific authorization checks.
//! Field values may be wire-valid while violating application invariants.
//! Callers should validate identities, ranges, lengths, and relationships too.
//!
//! # Decode size budgets
//!
//! `max_message_bytes` applies to the root and every embedded message.
//! The root check occurs before its first field is decoded.
//! Embedded-message length is checked before recursive decoding begins.
//! `max_length_delimited_bytes` applies to each string and bytes value.
//! It also applies to embedded messages, packed fields, and map entries.
//! Wire lengths are decoded as `u64` and converted with [`usize::try_from`].
//! A length that cannot fit the current target is rejected without truncation.
//! `max_recursion_depth` counts embedded-message edges below the root.
//! A limit of zero permits the root but rejects its first embedded message.
//! The compatibility default follows the conventional depth limit of 100.
//! Applications with smaller stacks should select a smaller explicit limit.
//! These checks are important on constrained 32-bit and embedded targets.
//!
//! # Decode collection budgets
//!
//! `max_field_occurrences` is shared across the complete decoded message tree.
//! It includes known fields, unknown fields, and synthetic map-entry fields.
//! This bounds floods made from many tiny tags even when values are discarded.
//! `max_repeated_values` applies independently to each repeated field.
//! Both packed elements and unpacked occurrences count toward the same limit.
//! Multiple packed segments continue accumulating against that shared bound.
//! `max_map_entries` bounds the distinct keys retained by each map field.
//! Duplicate keys do not increase retained size under last-key-wins behavior.
//! They still consume the global occurrence budget and can be rejected.
//! Limits use checked counters so counter overflow itself becomes an error.
//! The defaults remain permissive except for recursion depth.
//! Gateways should choose budgets from their actual protocol expectations.
//!
//! # Strict varint form
//!
//! `require_minimal_varints` covers keys, lengths, and scalar varint values.
//! Redundant continuation bytes are rejected even when the value would fit.
//! Field keys must still fit the protobuf five-byte and field-number bounds.
//! Strict 32-bit fields additionally reject lossy truncation from a `u64`.
//! This catches five-byte negative `int32` values that require ten bytes.
//! It also catches `uint32` and `sint32` inputs above their numeric width.
//! Known values are normally normalized by decode followed by encode.
//! Unknown values retain raw bytes unless strict decoding or dropping is used.
//! Strict form is useful before signatures, policy checks, or parser handoff.
//! It does not make the complete protobuf serialization canonical.
//!
//! # Unknown and duplicate policies
//!
//! [`UnknownFieldPolicy::Preserve`] retains normal compatibility behavior.
//! [`UnknownFieldPolicy::Drop`] omits the value but still creates audit evidence.
//! [`UnknownFieldPolicy::Reject`] fails at the first unknown field occurrence.
//! Length-delimited unknown data cannot be reliably classified without schema.
//! It might contain bytes, text, packed scalars, or an embedded message.
//! Dropping unknown data is therefore the strongest generic sanitization.
//! [`DuplicateInputPolicy::Allow`] applies protobuf merge and last-wins rules.
//! [`DuplicateInputPolicy::Reject`] rejects singular scalar repetitions.
//! It also rejects oneof conflicts, duplicate map keys, and duplicate entry data.
//! Repeated field occurrences are intentional and are never duplicates.
//! Strict duplicate rejection can prevent cross-parser interpretation variance.
//!
//! # Scalar-domain policies
//!
//! Protobuf normally interprets every nonzero boolean varint as true.
//! [`BooleanValuePolicy::RejectNonCanonical`] accepts only zero and one.
//! Open protobuf enums normally preserve numbers absent from the descriptor.
//! [`EnumValuePolicy::RejectUnknown`] restricts values to declared members.
//! That enum rule is an application sanitization choice, not proto3 default.
//! Signed and unsigned integer values otherwise follow protobuf cast semantics.
//! UTF-8 validation is unconditional for every descriptor-known string.
//! Bytes fields remain opaque and require application-level content checks.
//! Fixed-width floats retain all IEEE bit patterns during ordinary decoding.
//!
//! # Bounded auditing
//!
//! Full auditing copies each complete source occurrence for later inspection.
//! Nested data can appear in its own audit and in its containing field record.
//! `max_audit_bytes` bounds the cumulative bytes copied during one decode.
//! [`AuditMode::MetadataOnly`] retains provenance without copying source bytes.
//! Metadata-only records still identify names, numbers, wire types, and tags.
//! They can prove that unknown or duplicate data was observed and removed.
//! They cannot later reproduce a displaced raw occurrence byte-for-byte.
//! Encoding with [`DuplicatePolicy::PreserveAll`] therefore rejects such input.
//! Unknown values preserved in [`Message::unknown_fields`] remain independent.
//! Dropping unknown fields plus metadata-only audit minimizes payload copying.
//! Applications can persist or aggregate metadata after successful decoding.
//!
//! # Encoder normalization
//!
//! [`FieldOrder::FieldNumber`] stably sorts all complete wire occurrences.
//! Equal-number occurrences retain order for repeated-field correctness.
//! [`MapOrder::Key`] orders signed, unsigned, boolean, and string map keys.
//! Map values remain attached to their corresponding keys during sorting.
//! [`FloatEncoding::Normalize`] maps every NaN width to one quiet NaN pattern.
//! It also converts negative zero to positive zero before writing fixed bits.
//! Finite nonzero floating-point values retain their original IEEE value.
//! `max_output_bytes` rejects each completed root or embedded serialization.
//! The output limit is a final size guard rather than a streaming allocator.
//! Callers should also bound programmatically constructed collection sizes.
//! Unknown and application-added data can be filtered before size validation.
//! Numeric field ordering and map ordering improve local reproducibility.
//! Protobuf explicitly does not define a universal canonical byte encoding.
//!
//! # Determinism
//!
//! Descriptor fields serialize in declaration order.
//! Dynamic named fields use a `BTreeMap` for stable inspection order.
//! Repeated values serialize in their retained order.
//! Map values serialize in their retained insertion order.
//! Unknown fields serialize after schema-known fields.
//! Application-added raw fields serialize after received unknown fields.
//! Protobuf does not require a unique byte representation for a message.
//! Determinism here is therefore an implementation property, not canonicality.
//! Decoders must continue accepting semantically equivalent field orders.
//!
//! # Conformance
//!
//! The repository contains a host-only official conformance test adapter.
//! The adapter uses this dynamic API rather than generated Rust messages.
//! Proto3 binary required and recommended cases are exercised.
//! Basic proto2 binary cases are exercised with known MessageSet exclusions.
//! Protobuf JSON requests use the descriptor-driven JSON module.
//! Text-format and JSPB requests are explicitly skipped by the adapter.
//! `CONFORMANCE.md` records every ignored or unsupported family.
//! The vendored runner pins the upstream protobuf revision used for results.
//! None of the host-only conformance machinery is linked into this library.

use crate::{
    Cardinality, EnumType, Error, Field, FieldPresence, FieldType, MessageDescriptor,
    MessageEncoding, Result, Schema, Utf8Validation,
    constants::{
        CANONICAL_F32_NAN_BITS, CANONICAL_F64_NAN_BITS, DEFAULT_RECURSION_LIMIT,
        FIELD_NUMBER_SHIFT, FIXED32_SIZE, FIXED64_SIZE, HARDENED_MAX_AUDIT_BYTES,
        HARDENED_MAX_FIELD_OCCURRENCES, HARDENED_MAX_LENGTH_DELIMITED_BYTES,
        HARDENED_MAX_MAP_ENTRIES, HARDENED_MAX_MESSAGE_BYTES, HARDENED_MAX_REPEATED_VALUES,
        I32_SIGN_SHIFT, I64_SIGN_SHIFT, MAP_KEY_FIELD_NUMBER, MAP_VALUE_FIELD_NUMBER,
        MAX_FIELD_KEY_BYTES, MAX_FIELD_NUMBER, MAX_TENTH_VARINT_BYTE, MAX_VARINT_BYTES,
        MIN_FIELD_NUMBER, VARINT_BITS_PER_BYTE, VARINT_CONTINUATION_BIT, VARINT_DATA_MASK,
        WIRE_TYPE_END_GROUP, WIRE_TYPE_FIXED32, WIRE_TYPE_FIXED64, WIRE_TYPE_LENGTH_DELIMITED,
        WIRE_TYPE_MASK, WIRE_TYPE_START_GROUP, WIRE_TYPE_VARINT, is_supported_wire_type, make_key,
    },
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use core::{cmp::Ordering, ops::Range};
/// Runtime representation of any supported protobuf field value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// IEEE-754 double-precision value.
    Double(f64),
    /// IEEE-754 single-precision value.
    Float(f32),
    /// Signed 32-bit integer, including `sint32` and `sfixed32` values.
    Int32(i32),
    /// Signed 64-bit integer, including `sint64` and `sfixed64` values.
    Int64(i64),
    /// Unsigned 32-bit integer, including `fixed32` values.
    Uint32(u32),
    /// Unsigned 64-bit integer, including `fixed64` values.
    Uint64(u64),
    /// Boolean value.
    Bool(bool),
    /// UTF-8 string value.
    String(String),
    /// String payload retained without UTF-8 validation under Editions.
    RawString(Vec<u8>),
    /// Opaque byte-string value.
    Bytes(Vec<u8>),
    /// Numeric enum value, including values unknown to the schema.
    Enum(i32),
    /// Descriptor-driven embedded message.
    Message(Message),
    /// Ordered occurrences of a repeated field.
    Repeated(Vec<Value>),
    /// Protobuf map entries in deterministic insertion order.
    Map(Vec<(Value, Value)>),
}
/// Schema-external wire occurrence retained during decoding.
#[derive(Clone, Debug, PartialEq)]
pub struct UnknownField {
    /// Positive protobuf field number decoded from the wire key.
    pub number: u32,
    /// Protobuf binary wire-type identifier.
    pub wire_type: u8,
    /// Exact encoded value bytes excluding the field key.
    pub encoded_value: Vec<u8>,
}
/// A raw field supplied by the application without a schema declaration.
///
/// `encoded_value` contains the bytes after the field key, exactly like
/// [`UnknownField::encoded_value`]. Keeping the wire metadata makes forwarding
/// possible even though the registry has no descriptor for the field.
#[derive(Clone, Debug, PartialEq)]
pub struct AddedField {
    /// Application-facing name used to identify the added field.
    pub name: String,
    /// Positive protobuf field number to write into the wire key.
    pub number: u32,
    /// Protobuf binary wire-type identifier.
    pub wire_type: u8,
    /// Pre-encoded value bytes excluding the field key.
    pub encoded_value: Vec<u8>,
}

/// Identifies why an occurrence exists and how decoding treated it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditTag {
    /// The occurrence was declared by the parsed schema.
    SchemaField,
    /// The field number was absent from the schema.
    UnknownField,
    /// An unknown length-delimited occurrence may contain a nested message.
    UnknownMessage,
    /// The application added a raw field absent from the schema.
    AddedField,
    /// A later singular occurrence displaced this one under last-wins rules.
    DuplicateDiscarded,
    /// This occurrence won because it was the last singular value or map key.
    DuplicateLastWins,
    /// A repeated singular message occurrence was merged as protobuf requires.
    DuplicateMerged,
}

/// Controls whether unknown wire occurrences are retained after decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownFieldPolicy {
    /// Retain unknown values for forward-compatible reserialization.
    Preserve,
    /// Remove unknown values while retaining their audit metadata.
    Drop,
    /// Reject a message as soon as an unknown field number is encountered.
    Reject,
}

/// Controls how duplicate singular fields and duplicate map keys are handled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicateInputPolicy {
    /// Apply protobuf merge and last-wins rules while recording audit tags.
    Allow,
    /// Reject duplicate singular fields, oneof conflicts, and map keys.
    Reject,
}

/// Controls retention of original field bytes in decode audit records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditMode {
    /// Retain complete original field bytes subject to the audit-byte limit.
    Full,
    /// Retain tags and field metadata without copying original field bytes.
    MetadataOnly,
}

/// Controls interpretation of boolean varints other than zero and one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BooleanValuePolicy {
    /// Decode zero as false and every nonzero value as true.
    CoerceNonzero,
    /// Reject boolean varints whose numeric value is greater than one.
    RejectNonCanonical,
}

/// Controls whether enum numbers absent from the descriptor are accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnumValuePolicy {
    /// Preserve every signed 32-bit enum number, including unknown values.
    Preserve,
    /// Reject enum numbers not declared by the resolved enum descriptor.
    RejectUnknown,
}

/// Resource and normalization policies applied while decoding wire data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeOptions {
    /// Maximum size of each decoded root or embedded message.
    pub max_message_bytes: usize,
    /// Maximum embedded-message nesting below the root message.
    pub max_recursion_depth: usize,
    /// Maximum total field occurrences across the complete message tree.
    pub max_field_occurrences: usize,
    /// Maximum payload size of one length-delimited value.
    pub max_length_delimited_bytes: usize,
    /// Maximum retained values in any one repeated field.
    pub max_repeated_values: usize,
    /// Maximum retained entries in any one map field.
    pub max_map_entries: usize,
    /// Maximum cumulative original bytes copied into audit records.
    pub max_audit_bytes: usize,
    /// Unknown-field retention or rejection policy.
    pub unknown_fields: UnknownFieldPolicy,
    /// Duplicate singular-field and map-key policy.
    pub duplicates: DuplicateInputPolicy,
    /// Whether audit records retain complete original field bytes.
    pub audit_mode: AuditMode,
    /// Whether keys, lengths, and scalar varints must use minimal encoding.
    pub require_minimal_varints: bool,
    /// Boolean value-domain policy.
    pub booleans: BooleanValuePolicy,
    /// Enum value-domain policy.
    pub enum_values: EnumValuePolicy,
}

impl Default for DecodeOptions {
    /// Preserves protobuf-compatible behavior with a conventional depth limit.
    fn default() -> Self {
        Self {
            max_message_bytes: usize::MAX,
            max_recursion_depth: DEFAULT_RECURSION_LIMIT,
            max_field_occurrences: usize::MAX,
            max_length_delimited_bytes: usize::MAX,
            max_repeated_values: usize::MAX,
            max_map_entries: usize::MAX,
            max_audit_bytes: usize::MAX,
            unknown_fields: UnknownFieldPolicy::Preserve,
            duplicates: DuplicateInputPolicy::Allow,
            audit_mode: AuditMode::Full,
            require_minimal_varints: false,
            booleans: BooleanValuePolicy::CoerceNonzero,
            enum_values: EnumValuePolicy::Preserve,
        }
    }
}

impl DecodeOptions {
    /// Returns finite, strict defaults suitable for decoding hostile traffic.
    pub const fn hardened() -> Self {
        Self {
            max_message_bytes: HARDENED_MAX_MESSAGE_BYTES,
            max_recursion_depth: DEFAULT_RECURSION_LIMIT,
            max_field_occurrences: HARDENED_MAX_FIELD_OCCURRENCES,
            max_length_delimited_bytes: HARDENED_MAX_LENGTH_DELIMITED_BYTES,
            max_repeated_values: HARDENED_MAX_REPEATED_VALUES,
            max_map_entries: HARDENED_MAX_MAP_ENTRIES,
            max_audit_bytes: HARDENED_MAX_AUDIT_BYTES,
            unknown_fields: UnknownFieldPolicy::Reject,
            duplicates: DuplicateInputPolicy::Reject,
            audit_mode: AuditMode::MetadataOnly,
            require_minimal_varints: true,
            booleans: BooleanValuePolicy::RejectNonCanonical,
            enum_values: EnumValuePolicy::RejectUnknown,
        }
    }
}

/// Immutable evidence for one decoded or programmatically added occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    /// Classification describing the occurrence's provenance and treatment.
    pub tag: AuditTag,
    /// Descriptor or application field name, when one is available.
    pub field_name: Option<String>,
    /// Numeric protobuf field tag, or zero for name-only additions.
    pub field_number: u32,
    /// Protobuf binary wire-type identifier.
    pub wire_type: u8,
    /// Complete original field bytes, including the encoded field key.
    pub encoded_field: Vec<u8>,
}

/// Controls whether displaced singular occurrences are re-emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DuplicatePolicy {
    /// Emit only the value retained by protobuf's last-wins policy.
    LastOnly,
    /// Re-emit displaced raw occurrences before the retained value.
    PreserveAll,
}

/// Controls the order of serialized protobuf field occurrences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldOrder {
    /// Emit known fields in schema declaration order, then forwarded fields.
    Declaration,
    /// Stably sort every emitted occurrence by its numeric protobuf field ID.
    ///
    /// Repeated occurrences with the same field number retain their original
    /// relative order, preserving repeated-field and duplicate semantics.
    FieldNumber,
}

/// Controls serialization order for entries within each map field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapOrder {
    /// Preserve the map entry order retained by the dynamic message.
    Preserve,
    /// Sort entries by their protobuf key value before serialization.
    Key,
}

/// Controls normalization of floating-point bit patterns during encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatEncoding {
    /// Preserve finite values, signed zero, and NaN payload bits exactly.
    Preserve,
    /// Convert negative zero to positive zero and every NaN to one quiet NaN.
    Normalize,
}

/// Serialization controls for schema-external, duplicate, and ordered data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodeOptions {
    /// Whether unknown scalar and fixed-width occurrences are emitted.
    pub forward_unknown_fields: bool,
    /// Whether unknown length-delimited occurrences are emitted.
    pub forward_unknown_messages: bool,
    /// Whether raw application-added occurrences are emitted.
    pub forward_added_fields: bool,
    /// Policy controlling displaced duplicate singular occurrences.
    pub duplicates: DuplicatePolicy,
    /// Ordering policy applied to every emitted wire occurrence.
    pub field_order: FieldOrder,
    /// Ordering policy applied within each dynamically represented map.
    pub map_order: MapOrder,
    /// Floating-point bit-pattern normalization policy.
    pub floats: FloatEncoding,
    /// Maximum total serialized size of each root or embedded message.
    pub max_output_bytes: usize,
}

impl Default for EncodeOptions {
    /// Enables forwarding of schema-external data and keeps only retained
    /// singular values, matching protobuf's normal compatibility behavior.
    fn default() -> Self {
        Self {
            forward_unknown_fields: true,
            forward_unknown_messages: true,
            forward_added_fields: true,
            duplicates: DuplicatePolicy::LastOnly,
            field_order: FieldOrder::Declaration,
            map_order: MapOrder::Preserve,
            floats: FloatEncoding::Preserve,
            max_output_bytes: usize::MAX,
        }
    }
}

/// Encoded bytes accompanied by the complete audit trail used to produce them.
#[derive(Clone, Debug, PartialEq)]
pub struct EncodeOutput {
    /// Serialized protobuf binary message.
    pub bytes: Vec<u8>,
    /// Audit records considered while producing the serialized bytes.
    pub audit: Vec<AuditRecord>,
}

/// Allocation-backed dynamic protobuf message and its audit metadata.
#[derive(Clone, Debug, Default)]
pub struct Message {
    /// Descriptor-named semantic field values.
    pub fields: BTreeMap<String, Value>,
    /// Wire occurrences whose field numbers are absent from the descriptor.
    pub unknown_fields: Vec<UnknownField>,
    /// Raw schema-external fields supplied by the application.
    pub added_fields: Vec<AddedField>,
    /// Provenance and duplicate-handling records for wire occurrences.
    pub audit: Vec<AuditRecord>,
}
impl PartialEq for Message {
    /// Compares semantic fields while deliberately excluding audit metadata.
    fn eq(&self, other: &Self) -> bool {
        self.fields == other.fields
            && self.unknown_fields == other.unknown_fields
            && self.added_fields == other.added_fields
    }
}
impl Message {
    /// Creates an empty dynamic message with no fields or audit records.
    pub fn new() -> Self {
        Self::default()
    }
    /// Inserts or replaces a descriptor-named value.
    ///
    /// Returns the previous value when the name was already present.
    pub fn insert(&mut self, n: impl Into<String>, v: Value) -> Option<Value> {
        self.fields.insert(n.into(), v)
    }
    /// Returns the dynamic value stored under a descriptor field name.
    pub fn get(&self, n: &str) -> Option<&Value> {
        self.fields.get(n)
    }

    /// Adds a schema-external raw field and records its provenance immediately.
    pub fn add_field(&mut self, field: AddedField) {
        let mut encoded_field = Vec::new();
        vi(make_key(field.number, field.wire_type), &mut encoded_field);
        encoded_field.extend_from_slice(&field.encoded_value);
        self.audit.push(AuditRecord {
            tag: AuditTag::AddedField,
            field_name: Some(field.name.clone()),
            field_number: field.number,
            wire_type: field.wire_type,
            encoded_field,
        });
        self.added_fields.push(field);
    }
}
/// Appends an unsigned integer using protobuf's base-128 varint encoding.
fn vi(mut n: u64, o: &mut Vec<u8>) {
    while n > u64::from(VARINT_DATA_MASK) {
        o.push(n as u8 | VARINT_CONTINUATION_BIT);
        n >>= VARINT_BITS_PER_BYTE
    }
    o.push(n as u8)
}
/// Reads one unsigned protobuf varint and advances the input cursor.
///
/// Returns an error for truncation, values wider than 64 bits, or varints
/// longer than the protobuf ten-byte limit.
fn rv(b: &[u8], p: &mut usize) -> Result<u64> {
    read_varint(b, p, false)
}

/// Returns the shortest legal byte length for an unsigned varint value.
fn minimal_varint_length(mut value: u64) -> usize {
    let mut length = 1;
    while value > u64::from(VARINT_DATA_MASK) {
        value >>= VARINT_BITS_PER_BYTE;
        length += 1;
    }
    length
}

/// Reads a varint and optionally rejects a longer-than-minimal representation.
fn read_varint(b: &[u8], p: &mut usize, require_minimal: bool) -> Result<u64> {
    let s = *p;
    let mut n = 0;
    for byte_index in 0..MAX_VARINT_BYTES {
        let shift = byte_index * VARINT_BITS_PER_BYTE;
        let x = *b.get(*p).ok_or_else(|| Error::new(s, "truncated varint"))?;
        *p += 1;
        if byte_index + 1 == MAX_VARINT_BYTES && x > MAX_TENTH_VARINT_BYTE {
            return Err(Error::new(s, "varint overflow"));
        }
        n |= u64::from(x & VARINT_DATA_MASK) << shift;
        if x & VARINT_CONTINUATION_BIT == 0 {
            let encoded_length = p
                .checked_sub(s)
                .ok_or_else(|| Error::new(s, "varint cursor moved backwards"))?;
            if require_minimal && encoded_length != minimal_varint_length(n) {
                return Err(Error::new(s, "non-minimal varint encoding"));
            }
            return Ok(n);
        }
    }
    Err(Error::new(s, "varint overflow"))
}
/// Decodes and validates a protobuf field key at the current input cursor.
///
/// The returned pair contains the positive field number and its wire type.
fn read_key(b: &[u8], p: &mut usize) -> Result<(u32, u8)> {
    read_key_with_policy(b, p, false)
}

/// Decodes a field key under the selected minimal-varint policy.
fn read_key_with_policy(b: &[u8], p: &mut usize, require_minimal: bool) -> Result<(u32, u8)> {
    let start = *p;
    let key = read_varint(b, p, require_minimal)?;
    let encoded_size = p
        .checked_sub(start)
        .ok_or_else(|| Error::new(start, "field cursor moved backwards"))?;
    if encoded_size > MAX_FIELD_KEY_BYTES || key > u64::from(u32::MAX) {
        return Err(Error::new(start, "field tag exceeds 32 bits"));
    }
    let number = (key >> FIELD_NUMBER_SHIFT) as u32;
    if !(MIN_FIELD_NUMBER..=MAX_FIELD_NUMBER).contains(&number) {
        return Err(Error::new(start, "invalid field number in tag"));
    }
    Ok((number, (key & WIRE_TYPE_MASK) as u8))
}
/// Returns the protobuf binary wire type required by a resolved field type.
fn wire(t: &FieldType) -> u8 {
    match t {
        FieldType::Double | FieldType::Fixed64 | FieldType::Sfixed64 => WIRE_TYPE_FIXED64,
        FieldType::String | FieldType::Bytes | FieldType::Message(_) | FieldType::Map(..) => {
            WIRE_TYPE_LENGTH_DELIMITED
        }
        FieldType::Float | FieldType::Fixed32 | FieldType::Sfixed32 => WIRE_TYPE_FIXED32,
        _ => WIRE_TYPE_VARINT,
    }
}
/// Encodes one non-map, non-repeated value without writing its field key.
///
/// Nested messages inherit the caller's forwarding options. An error is
/// returned when the dynamic value does not match the descriptor field type.
fn scalar(
    t: &FieldType,
    v: &Value,
    s: &Schema,
    options: &EncodeOptions,
    o: &mut Vec<u8>,
) -> Result<()> {
    match (t, v) {
        (FieldType::Double, Value::Double(x)) => {
            let value = normalized_f64(*x, options.floats);
            o.extend(value.to_le_bytes());
        }
        (FieldType::Float, Value::Float(x)) => {
            let value = normalized_f32(*x, options.floats);
            o.extend(value.to_le_bytes());
        }
        (FieldType::Int32, Value::Int32(x)) => vi(*x as i64 as u64, o),
        (FieldType::Int64, Value::Int64(x)) => vi(*x as u64, o),
        (FieldType::Uint32, Value::Uint32(x)) => vi(*x as u64, o),
        (FieldType::Uint64, Value::Uint64(x)) => vi(*x, o),
        (FieldType::Sint32, Value::Int32(x)) => {
            vi(((*x << 1) ^ (*x >> I32_SIGN_SHIFT)) as u32 as u64, o)
        }
        (FieldType::Sint64, Value::Int64(x)) => vi(((*x << 1) ^ (*x >> I64_SIGN_SHIFT)) as u64, o),
        (FieldType::Fixed32, Value::Uint32(x)) => o.extend(x.to_le_bytes()),
        (FieldType::Fixed64, Value::Uint64(x)) => o.extend(x.to_le_bytes()),
        (FieldType::Sfixed32, Value::Int32(x)) => o.extend(x.to_le_bytes()),
        (FieldType::Sfixed64, Value::Int64(x)) => o.extend(x.to_le_bytes()),
        (FieldType::Bool, Value::Bool(x)) => vi(*x as u64, o),
        (FieldType::Enum(name), Value::Enum(x)) => {
            if s.enums.get(name).is_some_and(|enumeration| {
                enumeration.features.enum_type == EnumType::Closed
                    && !enumeration
                        .values
                        .iter()
                        .any(|candidate| candidate.number == *x)
            }) {
                return Err(Error::new(0, "unknown value for closed enum"));
            }
            vi(*x as i64 as u64, o);
        }
        (FieldType::String, Value::String(x)) => {
            ensure_output_growth(
                o.len(),
                minimal_varint_length(x.len() as u64),
                x.len(),
                options.max_output_bytes,
            )?;
            vi(x.len() as u64, o);
            o.extend(x.as_bytes())
        }
        (FieldType::Bytes, Value::Bytes(x)) => {
            ensure_output_growth(
                o.len(),
                minimal_varint_length(x.len() as u64),
                x.len(),
                options.max_output_bytes,
            )?;
            vi(x.len() as u64, o);
            o.extend(x)
        }
        (FieldType::Message(n), Value::Message(x)) => {
            let d = s
                .message(n)
                .ok_or_else(|| Error::new(0, "unknown message type"))?;
            let b = encode_inner(s, d, x, options)?.bytes;
            ensure_output_growth(
                o.len(),
                minimal_varint_length(b.len() as u64),
                b.len(),
                options.max_output_bytes,
            )?;
            vi(b.len() as u64, o);
            o.extend(b)
        }
        _ => return Err(Error::new(0, "value does not match field type")),
    }
    Ok(())
}

/// Rejects an append before it can grow an output buffer beyond its budget.
fn ensure_output_growth(
    current: usize,
    overhead: usize,
    payload: usize,
    limit: usize,
) -> Result<()> {
    let required = current
        .checked_add(overhead)
        .and_then(|value| value.checked_add(payload))
        .ok_or_else(|| Error::new(0, "encoded message size overflow"))?;
    if required > limit {
        return Err(Error::new(
            0,
            "encoded message exceeds configured size limit",
        ));
    }
    Ok(())
}

/// Applies the selected normalization policy to one 32-bit float.
fn normalized_f32(value: f32, policy: FloatEncoding) -> f32 {
    if policy == FloatEncoding::Normalize {
        if value.is_nan() {
            f32::from_bits(CANONICAL_F32_NAN_BITS)
        } else if value == 0.0 {
            0.0
        } else {
            value
        }
    } else {
        value
    }
}

/// Applies the selected normalization policy to one 64-bit float.
fn normalized_f64(value: f64, policy: FloatEncoding) -> f64 {
    if policy == FloatEncoding::Normalize {
        if value.is_nan() {
            f64::from_bits(CANONICAL_F64_NAN_BITS)
        } else if value == 0.0 {
            0.0
        } else {
            value
        }
    } else {
        value
    }
}

/// Compares two valid dynamic map keys according to their protobuf key type.
fn compare_map_keys(kind: &FieldType, left: &Value, right: &Value) -> Ordering {
    match (kind, left, right) {
        (
            FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32,
            Value::Int32(left),
            Value::Int32(right),
        ) => left.cmp(right),
        (
            FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64,
            Value::Int64(left),
            Value::Int64(right),
        ) => left.cmp(right),
        (FieldType::Uint32 | FieldType::Fixed32, Value::Uint32(left), Value::Uint32(right)) => {
            left.cmp(right)
        }
        (FieldType::Uint64 | FieldType::Fixed64, Value::Uint64(left), Value::Uint64(right)) => {
            left.cmp(right)
        }
        (FieldType::Bool, Value::Bool(left), Value::Bool(right)) => left.cmp(right),
        (FieldType::String, Value::String(left), Value::String(right)) => left.cmp(right),
        (FieldType::String, Value::RawString(left), Value::RawString(right)) => left.cmp(right),
        _ => Ordering::Equal,
    }
}
/// Serializes a dynamic message using the default forwarding policy.
///
/// # Errors
///
/// Returns an error for missing required fields, unknown referenced message
/// types, invalid added-field metadata, or values incompatible with the schema.
pub fn encode(s: &Schema, d: &MessageDescriptor, m: &Message) -> Result<Vec<u8>> {
    Ok(encode_with_options(s, d, m, &EncodeOptions::default())?.bytes)
}

/// Serializes a message while applying explicit forwarding policies.
///
/// The returned audit vector includes existing decode records and any
/// schema-absent named fields discovered during serialization.
///
/// # Errors
///
/// Returns the same validation errors as [`encode`]. Forwarding a named field
/// with no descriptor also fails because its wire metadata cannot be inferred.
pub fn encode_with_options(
    s: &Schema,
    d: &MessageDescriptor,
    m: &Message,
    options: &EncodeOptions,
) -> Result<EncodeOutput> {
    encode_inner(s, d, m, options)
}

/// Validates descriptor-level invariants that the open dynamic model cannot
/// express in its Rust types alone.
fn validate_message_shape(s: &Schema, d: &MessageDescriptor, m: &Message) -> Result<()> {
    let mut selected_oneofs = BTreeSet::new();
    for field in s.fields_for(d) {
        let Some(value) = m.get(&field.name) else {
            continue;
        };
        if let Some(oneof) = &field.oneof
            && !selected_oneofs.insert(oneof.as_str())
        {
            return Err(Error::new(0, "multiple values supplied for oneof"));
        }
        match (&field.kind, field.cardinality, value) {
            (FieldType::Map(_, _), _, Value::Map(entries)) => {
                for (index, (key, _)) in entries.iter().enumerate() {
                    if entries[..index].iter().any(|(previous, _)| previous == key) {
                        return Err(Error::new(0, "dynamic map contains duplicate keys"));
                    }
                }
            }
            (FieldType::Map(_, _), _, _) => {
                return Err(Error::new(0, "map field requires Value::Map"));
            }
            (_, Cardinality::Repeated, Value::Repeated(_)) => {}
            (_, Cardinality::Repeated, _) => {
                return Err(Error::new(0, "repeated field requires Value::Repeated"));
            }
            (_, _, Value::Repeated(_)) => {
                return Err(Error::new(
                    0,
                    "singular field cannot contain Value::Repeated",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Requires a public raw-field buffer to contain exactly one complete value.
fn validate_raw_field(number: u32, wire_type: u8, encoded_value: &[u8]) -> Result<()> {
    if !(MIN_FIELD_NUMBER..=MAX_FIELD_NUMBER).contains(&number)
        || !is_supported_wire_type(wire_type)
    {
        return Err(Error::new(0, "raw field has invalid wire metadata"));
    }
    let mut cursor = 0;
    skip(number, wire_type, encoded_value, &mut cursor)?;
    if cursor != encoded_value.len() {
        return Err(Error::new(cursor, "raw field contains trailing wire data"));
    }
    Ok(())
}

/// Validates a complete audit occurrence before duplicate replay.
fn validate_encoded_occurrence(record: &AuditRecord) -> Result<()> {
    let mut cursor = 0;
    let (number, wire_type) = read_key(&record.encoded_field, &mut cursor)?;
    if number != record.field_number || wire_type != record.wire_type {
        return Err(Error::new(
            0,
            "audit wire metadata does not match encoded field",
        ));
    }
    skip(number, wire_type, &record.encoded_field, &mut cursor)?;
    if cursor != record.encoded_field.len() {
        return Err(Error::new(
            cursor,
            "audit field contains trailing wire data",
        ));
    }
    Ok(())
}

/// Implements recursive serialization shared by the public encoding APIs.
fn encode_inner(
    s: &Schema,
    d: &MessageDescriptor,
    m: &Message,
    options: &EncodeOptions,
) -> Result<EncodeOutput> {
    validate_message_shape(s, d, m)?;
    let mut o = Vec::new();
    let mut audit = m.audit.clone();
    if options.duplicates == DuplicatePolicy::PreserveAll {
        for record in &m.audit {
            if record.tag == AuditTag::DuplicateDiscarded {
                if record.encoded_field.is_empty() {
                    return Err(Error::new(
                        0,
                        "cannot preserve duplicate without retained audit bytes",
                    ));
                }
                validate_encoded_occurrence(record)?;
                ensure_output_growth(
                    o.len(),
                    0,
                    record.encoded_field.len(),
                    options.max_output_bytes,
                )?;
                o.extend_from_slice(&record.encoded_field);
            }
        }
    }
    for f in s.fields_for(d) {
        if let Some(v) = m.get(&f.name) {
            if let FieldType::Map(key_type, value_type) = &f.kind {
                let Value::Map(entries) = v else {
                    return Err(Error::new(0, "map field requires Value::Map"));
                };
                let mut ordered_entries: Vec<_> = entries.iter().collect();
                if options.map_order == MapOrder::Key {
                    ordered_entries
                        .sort_by(|left, right| compare_map_keys(key_type, &left.0, &right.0));
                }
                for (key, value) in ordered_entries {
                    let mut entry = Vec::new();
                    vi(make_key(MAP_KEY_FIELD_NUMBER, wire(key_type)), &mut entry);
                    scalar(key_type, key, s, options, &mut entry)?;
                    vi(
                        make_key(MAP_VALUE_FIELD_NUMBER, wire(value_type)),
                        &mut entry,
                    );
                    scalar(value_type, value, s, options, &mut entry)?;
                    ensure_output_growth(
                        o.len(),
                        minimal_varint_length(make_key(f.number, WIRE_TYPE_LENGTH_DELIMITED))
                            + minimal_varint_length(entry.len() as u64),
                        entry.len(),
                        options.max_output_bytes,
                    )?;
                    vi(make_key(f.number, WIRE_TYPE_LENGTH_DELIMITED), &mut o);
                    vi(entry.len() as u64, &mut o);
                    o.extend(entry);
                }
                continue;
            }
            if !f.explicit_presence && is_default(v) {
                continue;
            }
            let xs = if let Value::Repeated(x) = v {
                x.as_slice()
            } else {
                core::slice::from_ref(v)
            };
            if xs.is_empty() {
                continue;
            }
            let pack = matches!(v, Value::Repeated(_)) && f.packed.unwrap_or(false);
            if pack {
                let mut z = Vec::new();
                for x in xs {
                    scalar(&f.kind, x, s, options, &mut z)?
                }
                ensure_output_growth(
                    o.len(),
                    minimal_varint_length(make_key(f.number, WIRE_TYPE_LENGTH_DELIMITED))
                        + minimal_varint_length(z.len() as u64),
                    z.len(),
                    options.max_output_bytes,
                )?;
                vi(make_key(f.number, WIRE_TYPE_LENGTH_DELIMITED), &mut o);
                vi(z.len() as u64, &mut o);
                o.extend(z)
            } else {
                for x in xs {
                    if matches!(f.kind, FieldType::Message(_))
                        && f.features.message_encoding == MessageEncoding::Delimited
                    {
                        let (FieldType::Message(name), Value::Message(message)) = (&f.kind, x)
                        else {
                            return Err(Error::new(0, "value does not match message field type"));
                        };
                        let nested = s
                            .message(name)
                            .ok_or_else(|| Error::new(0, "unknown message type"))?;
                        vi(make_key(f.number, WIRE_TYPE_START_GROUP), &mut o);
                        o.extend(encode_inner(s, nested, message, options)?.bytes);
                        vi(make_key(f.number, WIRE_TYPE_END_GROUP), &mut o);
                    } else {
                        vi(make_key(f.number, wire(&f.kind)), &mut o);
                        if let (FieldType::String, Value::RawString(bytes)) = (&f.kind, x) {
                            if f.features.utf8_validation != Utf8Validation::None {
                                return Err(Error::new(
                                    0,
                                    "raw string requires utf8_validation = NONE",
                                ));
                            }
                            ensure_output_growth(
                                o.len(),
                                minimal_varint_length(bytes.len() as u64),
                                bytes.len(),
                                options.max_output_bytes,
                            )?;
                            vi(bytes.len() as u64, &mut o);
                            o.extend(bytes);
                        } else {
                            scalar(&f.kind, x, s, options, &mut o)?
                        }
                    }
                }
            }
        } else if f.cardinality == Cardinality::Required
            || f.features.field_presence == FieldPresence::LegacyRequired
        {
            return Err(Error::new(0, "missing required field"));
        }
    }
    for u in &m.unknown_fields {
        let forward = if matches!(
            u.wire_type,
            WIRE_TYPE_LENGTH_DELIMITED | WIRE_TYPE_START_GROUP
        ) {
            options.forward_unknown_messages
        } else {
            options.forward_unknown_fields
        };
        if forward {
            validate_raw_field(u.number, u.wire_type, &u.encoded_value)?;
            ensure_output_growth(
                o.len(),
                minimal_varint_length(make_key(u.number, u.wire_type)),
                u.encoded_value.len(),
                options.max_output_bytes,
            )?;
            vi(make_key(u.number, u.wire_type), &mut o);
            o.extend_from_slice(&u.encoded_value)
        }
    }
    if options.forward_added_fields {
        for field in &m.added_fields {
            validate_raw_field(field.number, field.wire_type, &field.encoded_value)?;
            ensure_output_growth(
                o.len(),
                minimal_varint_length(make_key(field.number, field.wire_type)),
                field.encoded_value.len(),
                options.max_output_bytes,
            )?;
            vi(make_key(field.number, field.wire_type), &mut o);
            o.extend_from_slice(&field.encoded_value);
        }
    }
    for name in m.fields.keys() {
        if !s.fields_for(d).any(|field| field.name == *name) {
            audit.push(AuditRecord {
                tag: AuditTag::AddedField,
                field_name: Some(name.clone()),
                field_number: 0,
                wire_type: 0,
                encoded_field: Vec::new(),
            });
            if options.forward_added_fields {
                return Err(Error::new(
                    0,
                    "schema-absent named field needs raw wire metadata via Message::add_field",
                ));
            }
        }
    }
    apply_field_order(&mut o, options.field_order)?;
    if o.len() > options.max_output_bytes {
        return Err(Error::new(
            0,
            "encoded message exceeds configured size limit",
        ));
    }
    Ok(EncodeOutput { bytes: o, audit })
}

/// Applies the requested stable ordering to complete encoded occurrences.
///
/// Sorting happens after forwarding filters are applied, so known, unknown,
/// application-added, and preserved duplicate fields participate uniformly.
fn apply_field_order(bytes: &mut Vec<u8>, order: FieldOrder) -> Result<()> {
    if order == FieldOrder::Declaration {
        return Ok(());
    }
    let mut cursor = 0;
    let mut occurrences = Vec::new();
    while cursor < bytes.len() {
        let start = cursor;
        let (number, wire_type) = read_key(bytes, &mut cursor)?;
        skip(number, wire_type, bytes, &mut cursor)?;
        occurrences.push((number, audit_bytes(bytes, start, cursor)?));
    }
    occurrences.sort_by_key(|(number, _)| *number);
    bytes.clear();
    for (_, occurrence) in occurrences {
        bytes.extend_from_slice(&occurrence);
    }
    Ok(())
}
/// Reports whether a value is a protobuf implicit-presence default.
fn is_default(value: &Value) -> bool {
    match value {
        Value::Double(value) => *value == 0.0,
        Value::Float(value) => *value == 0.0,
        Value::Int32(value) | Value::Enum(value) => *value == 0,
        Value::Int64(value) => *value == 0,
        Value::Uint32(value) => *value == 0,
        Value::Uint64(value) => *value == 0,
        Value::Bool(value) => !*value,
        Value::String(value) => value.is_empty(),
        Value::RawString(value) => value.is_empty(),
        Value::Bytes(value) => value.is_empty(),
        Value::Repeated(value) => value.is_empty(),
        Value::Map(value) => value.is_empty(),
        Value::Message(_) => false,
    }
}

/// Applies protobuf's recursive merge rules to singular message occurrences.
fn merge_message(existing: &mut Message, mut incoming: Message) {
    for (name, value) in incoming.fields {
        match (existing.fields.get_mut(&name), value) {
            (Some(Value::Message(old)), Value::Message(new)) => merge_message(old, new),
            (Some(Value::Repeated(old)), Value::Repeated(mut new)) => old.append(&mut new),
            (Some(Value::Map(old)), Value::Map(new)) => {
                for (key, value) in new {
                    if let Some(entry) = old.iter_mut().find(|(candidate, _)| candidate == &key) {
                        entry.1 = value;
                    } else {
                        old.push((key, value));
                    }
                }
            }
            (_, value) => {
                existing.fields.insert(name, value);
            }
        }
    }
    existing.unknown_fields.append(&mut incoming.unknown_fields);
    existing.added_fields.append(&mut incoming.added_fields);
    existing.audit.append(&mut incoming.audit);
}
/// Borrows exactly `n` input bytes and advances the cursor after bounds checks.
fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = p
        .checked_add(n)
        .ok_or_else(|| Error::new(*p, "field length overflow"))?;
    let x = b
        .get(*p..end)
        .ok_or_else(|| Error::new(*p, "truncated field"))?;
    *p = end;
    Ok(x)
}
/// Reads an exact fixed-width value into an array without panicking on conversion.
fn fixed_bytes<const SIZE: usize>(b: &[u8], p: &mut usize) -> Result<[u8; SIZE]> {
    let start = *p;
    take(b, p, SIZE)?
        .try_into()
        .map_err(|_| Error::new(start, "invalid fixed-width field"))
}

/// Copies a validated input range for an audit record.
fn audit_bytes(b: &[u8], start: usize, end: usize) -> Result<Vec<u8>> {
    b.get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::new(start, "invalid audit byte range"))
}

/// Shared counters and policies for one recursive decode operation.
struct DecodeContext<'a> {
    /// Caller-selected limits and strictness policies.
    options: &'a DecodeOptions,
    /// Total wire occurrences observed across root and embedded messages.
    field_occurrences: usize,
    /// Total original wire bytes copied into full audit records.
    audit_bytes: usize,
}

impl DecodeContext<'_> {
    /// Accounts for one field occurrence before decoding its value.
    fn count_field(&mut self, offset: usize) -> Result<()> {
        self.field_occurrences = self
            .field_occurrences
            .checked_add(1)
            .ok_or_else(|| Error::new(offset, "field occurrence counter overflow"))?;
        if self.field_occurrences > self.options.max_field_occurrences {
            return Err(Error::new(
                offset,
                "message exceeds configured field occurrence limit",
            ));
        }
        Ok(())
    }

    /// Reads a scalar, key, or length varint under the configured strictness.
    fn varint(&self, bytes: &[u8], cursor: &mut usize) -> Result<u64> {
        read_varint(bytes, cursor, self.options.require_minimal_varints)
    }

    /// Reads a checked platform-sized length and applies its payload limit.
    fn length(&self, bytes: &[u8], cursor: &mut usize) -> Result<usize> {
        let offset = *cursor;
        let length = usize::try_from(self.varint(bytes, cursor)?)
            .map_err(|_| Error::new(offset, "length does not fit this target"))?;
        if length > self.options.max_length_delimited_bytes {
            return Err(Error::new(
                offset,
                "length-delimited value exceeds configured size limit",
            ));
        }
        Ok(length)
    }

    /// Creates an audit record while enforcing byte-retention limits.
    fn audit_record(
        &mut self,
        bytes: &[u8],
        range: Range<usize>,
        mut record: AuditRecord,
    ) -> Result<AuditRecord> {
        let encoded_field = if self.options.audit_mode == AuditMode::Full {
            let length = range
                .end
                .checked_sub(range.start)
                .ok_or_else(|| Error::new(range.start, "audit cursor moved backwards"))?;
            self.audit_bytes = self
                .audit_bytes
                .checked_add(length)
                .ok_or_else(|| Error::new(range.start, "audit byte counter overflow"))?;
            if self.audit_bytes > self.options.max_audit_bytes {
                return Err(Error::new(
                    range.start,
                    "message exceeds configured audit byte limit",
                ));
            }
            audit_bytes(bytes, range.start, range.end)?
        } else {
            Vec::new()
        };
        record.encoded_field = encoded_field;
        Ok(record)
    }
}

/// Decodes one descriptor-known scalar or embedded-message value.
///
/// The function checks that the encountered wire type matches the schema and
/// advances `p` past the decoded value.
fn val(
    t: &FieldType,
    w: u8,
    b: &[u8],
    p: &mut usize,
    s: &Schema,
    context: &mut DecodeContext<'_>,
    depth: usize,
) -> Result<Value> {
    if w != wire(t) {
        return Err(Error::new(*p, "wrong wire type"));
    }
    Ok(match t {
        FieldType::Double => Value::Double(f64::from_le_bytes(fixed_bytes::<FIXED64_SIZE>(b, p)?)),
        FieldType::Float => Value::Float(f32::from_le_bytes(fixed_bytes::<FIXED32_SIZE>(b, p)?)),
        FieldType::Int32 => {
            let raw = context.varint(b, p)?;
            let value = raw as i32;
            require_canonical_32_bit_varint(raw, value as i64 as u64, *p, context)?;
            Value::Int32(value)
        }
        FieldType::Int64 => Value::Int64(context.varint(b, p)? as i64),
        FieldType::Uint32 => {
            let raw = context.varint(b, p)?;
            let value = raw as u32;
            require_canonical_32_bit_varint(raw, u64::from(value), *p, context)?;
            Value::Uint32(value)
        }
        FieldType::Uint64 => Value::Uint64(context.varint(b, p)?),
        FieldType::Sint32 => {
            let raw = context.varint(b, p)?;
            let n = raw as u32;
            require_canonical_32_bit_varint(raw, u64::from(n), *p, context)?;
            Value::Int32((n >> 1) as i32 ^ -((n & 1) as i32))
        }
        FieldType::Sint64 => {
            let n = context.varint(b, p)?;
            Value::Int64((n >> 1) as i64 ^ -((n & 1) as i64))
        }
        FieldType::Fixed32 => Value::Uint32(u32::from_le_bytes(fixed_bytes::<FIXED32_SIZE>(b, p)?)),
        FieldType::Fixed64 => Value::Uint64(u64::from_le_bytes(fixed_bytes::<FIXED64_SIZE>(b, p)?)),
        FieldType::Sfixed32 => Value::Int32(i32::from_le_bytes(fixed_bytes::<FIXED32_SIZE>(b, p)?)),
        FieldType::Sfixed64 => Value::Int64(i64::from_le_bytes(fixed_bytes::<FIXED64_SIZE>(b, p)?)),
        FieldType::Bool => {
            let raw = context.varint(b, p)?;
            if raw > 1 && context.options.booleans == BooleanValuePolicy::RejectNonCanonical {
                return Err(Error::new(*p, "non-canonical boolean value"));
            }
            Value::Bool(raw != 0)
        }
        FieldType::Enum(name) => {
            let raw = context.varint(b, p)?;
            let value = raw as i32;
            require_canonical_32_bit_varint(raw, value as i64 as u64, *p, context)?;
            if context.options.enum_values == EnumValuePolicy::RejectUnknown
                && !s.enums.get(name).is_some_and(|enumeration| {
                    enumeration
                        .values
                        .iter()
                        .any(|candidate| candidate.number == value)
                })
            {
                return Err(Error::new(*p, "unknown enum value rejected by policy"));
            }
            Value::Enum(value)
        }
        FieldType::String => {
            let n = context.length(b, p)?;
            Value::String(
                core::str::from_utf8(take(b, p, n)?)
                    .map_err(|_| Error::new(*p, "invalid UTF-8"))?
                    .to_string(),
            )
        }
        FieldType::Bytes => {
            let n = context.length(b, p)?;
            Value::Bytes(take(b, p, n)?.to_vec())
        }
        FieldType::Message(n) => {
            let z = context.length(b, p)?;
            let q = take(b, p, z)?;
            Value::Message(decode_inner(
                s,
                s.message(n)
                    .ok_or_else(|| Error::new(*p, "unknown message type"))?,
                q,
                context,
                depth
                    .checked_add(1)
                    .ok_or_else(|| Error::new(*p, "recursion depth overflow"))?,
            )?)
        }
        FieldType::Map(..) => return Err(Error::new(*p, "map codec not yet supported")),
    })
}

/// Locates a matching group terminator and returns its body without decoding it.
fn delimited_message_body<'a>(
    field_number: u32,
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8]> {
    let body_start = *cursor;
    let mut scan = *cursor;
    loop {
        if scan == bytes.len() {
            return Err(Error::new(scan, "unterminated delimited message"));
        }
        let tag_start = scan;
        let (nested_number, nested_wire_type) = read_key(bytes, &mut scan)?;
        if nested_wire_type == WIRE_TYPE_END_GROUP {
            if nested_number != field_number {
                return Err(Error::new(scan, "mismatched delimited message terminator"));
            }
            *cursor = scan;
            return bytes
                .get(body_start..tag_start)
                .ok_or_else(|| Error::new(body_start, "invalid delimited message bounds"));
        }
        skip(nested_number, nested_wire_type, bytes, &mut scan)?;
    }
}

/// Decodes one field while honoring its resolved message-encoding feature.
fn field_value(
    field: &Field,
    wire_type: u8,
    bytes: &[u8],
    cursor: &mut usize,
    schema: &Schema,
    context: &mut DecodeContext<'_>,
    depth: usize,
) -> Result<Value> {
    if matches!(field.kind, FieldType::String)
        && field.features.utf8_validation == Utf8Validation::None
    {
        if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
            return Err(Error::new(*cursor, "string has wrong wire type"));
        }
        let length = context.length(bytes, cursor)?;
        return Ok(Value::RawString(take(bytes, cursor, length)?.to_vec()));
    }
    if field.features.message_encoding != MessageEncoding::Delimited
        || !matches!(field.kind, FieldType::Message(_))
    {
        return val(
            &field.kind,
            wire_type,
            bytes,
            cursor,
            schema,
            context,
            depth,
        );
    }
    let FieldType::Message(name) = &field.kind else {
        return Err(Error::new(
            *cursor,
            "DELIMITED message encoding requires a message field",
        ));
    };
    if wire_type != WIRE_TYPE_START_GROUP {
        return Err(Error::new(*cursor, "delimited message has wrong wire type"));
    }
    let body = delimited_message_body(field.number, bytes, cursor)?;
    let nested = schema
        .message(name)
        .ok_or_else(|| Error::new(*cursor, "unknown message type"))?;
    let nested_depth = depth
        .checked_add(1)
        .ok_or_else(|| Error::new(*cursor, "recursion depth overflow"))?;
    Ok(Value::Message(decode_inner(
        schema,
        nested,
        body,
        context,
        nested_depth,
    )?))
}

/// Rejects lossy 64-to-32-bit varint truncation in strict decoding mode.
fn require_canonical_32_bit_varint(
    raw: u64,
    canonical: u64,
    offset: usize,
    context: &DecodeContext<'_>,
) -> Result<()> {
    if context.options.require_minimal_varints && raw != canonical {
        return Err(Error::new(offset, "non-canonical 32-bit varint value"));
    }
    Ok(())
}

/// Constructs the protobuf default value for a map-entry component type.
fn default_value(t: &FieldType) -> Result<Value> {
    Ok(match t {
        FieldType::Double => Value::Double(0.0),
        FieldType::Float => Value::Float(0.0),
        FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 => Value::Int32(0),
        FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => Value::Int64(0),
        FieldType::Uint32 | FieldType::Fixed32 => Value::Uint32(0),
        FieldType::Uint64 | FieldType::Fixed64 => Value::Uint64(0),
        FieldType::Bool => Value::Bool(false),
        FieldType::String => Value::String(String::new()),
        FieldType::Bytes => Value::Bytes(Vec::new()),
        FieldType::Enum(_) => Value::Enum(0),
        FieldType::Message(_) => Value::Message(Message::new()),
        FieldType::Map(..) => return Err(Error::new(0, "a map cannot be a map value")),
    })
}

/// Decodes one length-delimited synthetic map-entry message.
///
/// Missing key or value components receive their protobuf defaults. Unknown
/// entry fields are skipped without escaping the declared entry boundary.
fn decode_map_entry(
    key_type: &FieldType,
    value_type: &FieldType,
    b: &[u8],
    p: &mut usize,
    s: &Schema,
    context: &mut DecodeContext<'_>,
    depth: usize,
) -> Result<(Value, Value)> {
    let length = context.length(b, p)?;
    let entry = take(b, p, length)?;
    let mut cursor = 0;
    let mut key = None;
    let mut value = None;
    while cursor < entry.len() {
        context.count_field(cursor)?;
        let tag = context.varint(entry, &mut cursor)?;
        match tag >> FIELD_NUMBER_SHIFT {
            field if field == u64::from(MAP_KEY_FIELD_NUMBER) => {
                if key.is_some() && context.options.duplicates == DuplicateInputPolicy::Reject {
                    return Err(Error::new(
                        cursor,
                        "duplicate map-entry key rejected by policy",
                    ));
                }
                key = Some(val(
                    key_type,
                    (tag & WIRE_TYPE_MASK) as u8,
                    entry,
                    &mut cursor,
                    s,
                    context,
                    depth,
                )?)
            }
            field if field == u64::from(MAP_VALUE_FIELD_NUMBER) => {
                if value.is_some() && context.options.duplicates == DuplicateInputPolicy::Reject {
                    return Err(Error::new(
                        cursor,
                        "duplicate map-entry value rejected by policy",
                    ));
                }
                value = Some(val(
                    value_type,
                    (tag & WIRE_TYPE_MASK) as u8,
                    entry,
                    &mut cursor,
                    s,
                    context,
                    depth,
                )?)
            }
            _ => {
                skip_decode(
                    tag as u32 >> FIELD_NUMBER_SHIFT,
                    (tag & WIRE_TYPE_MASK) as u8,
                    entry,
                    &mut cursor,
                    context,
                    depth,
                )?;
            }
        }
    }
    Ok((
        key.unwrap_or(default_value(key_type)?),
        value.unwrap_or(default_value(value_type)?),
    ))
}
/// Skips one unknown wire value and returns its exact encoded value bytes.
///
/// The returned bytes exclude the already-consumed field key. Groups include
/// their matching end tag so an unknown occurrence can be forwarded exactly.
fn skip(field_number: u32, w: u8, b: &[u8], p: &mut usize) -> Result<Vec<u8>> {
    let s = *p;
    match w {
        WIRE_TYPE_VARINT => {
            rv(b, p)?;
        }
        WIRE_TYPE_FIXED64 => {
            take(b, p, FIXED64_SIZE)?;
        }
        WIRE_TYPE_LENGTH_DELIMITED => {
            let offset = *p;
            let n = usize::try_from(rv(b, p)?)
                .map_err(|_| Error::new(offset, "length does not fit this target"))?;
            take(b, p, n)?;
        }
        WIRE_TYPE_FIXED32 => {
            take(b, p, FIXED32_SIZE)?;
        }
        WIRE_TYPE_START_GROUP => loop {
            if *p == b.len() {
                return Err(Error::new(*p, "unterminated group"));
            }
            let (nested_number, nested_wire_type) = read_key(b, p)?;
            if nested_wire_type == WIRE_TYPE_END_GROUP {
                if nested_number != field_number {
                    return Err(Error::new(*p, "mismatched end-group field number"));
                }
                break;
            }
            skip(nested_number, nested_wire_type, b, p)?;
        },
        WIRE_TYPE_END_GROUP => return Err(Error::new(*p, "unexpected end-group tag")),
        _ => return Err(Error::new(*p, "unsupported wire type")),
    }
    audit_bytes(b, s, *p)
}

/// Skips one unknown value under decode length and varint policies.
fn skip_decode(
    field_number: u32,
    wire_type: u8,
    bytes: &[u8],
    cursor: &mut usize,
    context: &mut DecodeContext<'_>,
    depth: usize,
) -> Result<Vec<u8>> {
    let start = *cursor;
    match wire_type {
        WIRE_TYPE_VARINT => {
            context.varint(bytes, cursor)?;
        }
        WIRE_TYPE_FIXED64 => {
            take(bytes, cursor, FIXED64_SIZE)?;
        }
        WIRE_TYPE_LENGTH_DELIMITED => {
            let length = context.length(bytes, cursor)?;
            take(bytes, cursor, length)?;
        }
        WIRE_TYPE_FIXED32 => {
            take(bytes, cursor, FIXED32_SIZE)?;
        }
        WIRE_TYPE_START_GROUP => {
            let nested_depth = depth
                .checked_add(1)
                .ok_or_else(|| Error::new(*cursor, "recursion depth overflow"))?;
            if nested_depth > context.options.max_recursion_depth {
                return Err(Error::new(
                    *cursor,
                    "group exceeds configured recursion limit",
                ));
            }
            loop {
                if *cursor == bytes.len() {
                    return Err(Error::new(*cursor, "unterminated group"));
                }
                let field_start = *cursor;
                context.count_field(field_start)?;
                let (nested_number, nested_wire_type) =
                    read_key_with_policy(bytes, cursor, context.options.require_minimal_varints)?;
                if nested_wire_type == WIRE_TYPE_END_GROUP {
                    if nested_number != field_number {
                        return Err(Error::new(*cursor, "mismatched end-group field number"));
                    }
                    break;
                }
                skip_decode(
                    nested_number,
                    nested_wire_type,
                    bytes,
                    cursor,
                    context,
                    nested_depth,
                )?;
            }
        }
        WIRE_TYPE_END_GROUP => return Err(Error::new(*cursor, "unexpected end-group tag")),
        _ => return Err(Error::new(*cursor, "unsupported wire type")),
    }
    audit_bytes(bytes, start, *cursor)
}
/// Decodes protobuf binary bytes into a descriptor-driven dynamic message.
///
/// Unknown fields, duplicate occurrences, and schema-known occurrences are
/// retained in the message's audit data according to protobuf merge rules.
///
/// # Errors
///
/// Returns an error for malformed wire data, type mismatches, unsupported
/// group wire types, unresolved nested descriptors, or missing required fields.
pub fn decode(s: &Schema, d: &MessageDescriptor, b: &[u8]) -> Result<Message> {
    decode_with_options(s, d, b, &DecodeOptions::default())
}

/// Decodes wire bytes while applying explicit resource and sanitization rules.
///
/// # Errors
///
/// Returns the same structural errors as [`decode`], plus errors selected by
/// resource limits, strict minimal-varint validation, unknown-field rejection,
/// or duplicate rejection.
pub fn decode_with_options(
    schema: &Schema,
    descriptor: &MessageDescriptor,
    bytes: &[u8],
    options: &DecodeOptions,
) -> Result<Message> {
    let mut context = DecodeContext {
        options,
        field_occurrences: 0,
        audit_bytes: 0,
    };
    decode_inner(schema, descriptor, bytes, &mut context, 0)
}

/// Recursively decodes one descriptor-bounded message with shared counters.
fn decode_inner(
    s: &Schema,
    d: &MessageDescriptor,
    b: &[u8],
    context: &mut DecodeContext<'_>,
    depth: usize,
) -> Result<Message> {
    if depth > context.options.max_recursion_depth {
        return Err(Error::new(0, "message exceeds configured recursion limit"));
    }
    if b.len() > context.options.max_message_bytes {
        return Err(Error::new(0, "message exceeds configured input size limit"));
    }
    let (mut m, mut p) = (Message::new(), 0);
    while p < b.len() {
        let field_start = p;
        context.count_field(field_start)?;
        let (n, w) = read_key_with_policy(b, &mut p, context.options.require_minimal_varints)?;
        let Some(f) = s.field_by_number(d, n) else {
            let encoded_value = skip_decode(n, w, b, &mut p, context, depth)?;
            if context.options.unknown_fields == UnknownFieldPolicy::Reject {
                return Err(Error::new(field_start, "unknown field rejected by policy"));
            }
            if context.options.unknown_fields == UnknownFieldPolicy::Preserve {
                m.unknown_fields.push(UnknownField {
                    number: n,
                    wire_type: w,
                    encoded_value,
                });
            }
            let tag = if matches!(w, WIRE_TYPE_LENGTH_DELIMITED | WIRE_TYPE_START_GROUP) {
                AuditTag::UnknownMessage
            } else {
                AuditTag::UnknownField
            };
            let record = context.audit_record(
                b,
                field_start..p,
                AuditRecord {
                    tag,
                    field_name: None,
                    field_number: n,
                    wire_type: w,
                    encoded_field: Vec::new(),
                },
            )?;
            m.audit.push(record);
            continue;
        };
        if let FieldType::Map(key_type, value_type) = &f.kind {
            if w != WIRE_TYPE_LENGTH_DELIMITED {
                return Err(Error::new(p, "map field has wrong wire type"));
            }
            let (key, value) =
                decode_map_entry(key_type, value_type, b, &mut p, s, context, depth)?;
            let mut entries = match m.fields.remove(&f.name) {
                Some(Value::Map(entries)) => entries,
                _ => Vec::new(),
            };
            // The protobuf map wire format permits duplicate keys; the last
            // occurrence wins, matching generated protobuf implementations.
            let duplicate = entries.iter().any(|(candidate, _)| candidate == &key);
            if duplicate && context.options.duplicates == DuplicateInputPolicy::Reject {
                return Err(Error::new(
                    field_start,
                    "duplicate map key rejected by policy",
                ));
            }
            if let Some(existing) = entries.iter_mut().find(|(candidate, _)| candidate == &key) {
                existing.1 = value;
            } else {
                if entries.len() >= context.options.max_map_entries {
                    return Err(Error::new(
                        field_start,
                        "map exceeds configured entry limit",
                    ));
                }
                entries.push((key, value));
            }
            m.insert(f.name.clone(), Value::Map(entries));
            if duplicate
                && let Some(previous) = m.audit.iter_mut().rev().find(|record| {
                    record.field_name.as_deref() == Some(&f.name)
                        && matches!(
                            record.tag,
                            AuditTag::SchemaField | AuditTag::DuplicateLastWins
                        )
                })
            {
                previous.tag = AuditTag::DuplicateDiscarded;
            }
            let tag = if duplicate {
                AuditTag::DuplicateLastWins
            } else {
                AuditTag::SchemaField
            };
            let record = context.audit_record(
                b,
                field_start..p,
                AuditRecord {
                    tag,
                    field_name: Some(f.name.clone()),
                    field_number: n,
                    wire_type: w,
                    encoded_field: Vec::new(),
                },
            )?;
            m.audit.push(record);
            continue;
        }
        if let FieldType::Enum(name) = &f.kind
            && w == WIRE_TYPE_VARINT
            && s.enums
                .get(name)
                .is_some_and(|enumeration| enumeration.features.enum_type == EnumType::Closed)
        {
            let value_start = p;
            let raw = context.varint(b, &mut p)?;
            let value = raw as i32;
            require_canonical_32_bit_varint(raw, value as i64 as u64, p, context)?;
            let known = s.enums.get(name).is_some_and(|enumeration| {
                enumeration
                    .values
                    .iter()
                    .any(|candidate| candidate.number == value)
            });
            if !known {
                if context.options.unknown_fields == UnknownFieldPolicy::Reject {
                    return Err(Error::new(field_start, "closed enum value is unknown"));
                }
                if context.options.unknown_fields == UnknownFieldPolicy::Preserve {
                    m.unknown_fields.push(UnknownField {
                        number: f.number,
                        wire_type: w,
                        encoded_value: audit_bytes(b, value_start, p)?,
                    });
                }
                let record = context.audit_record(
                    b,
                    field_start..p,
                    AuditRecord {
                        tag: AuditTag::UnknownField,
                        field_name: Some(f.name.clone()),
                        field_number: n,
                        wire_type: w,
                        encoded_field: Vec::new(),
                    },
                )?;
                m.audit.push(record);
                continue;
            }
            p = value_start;
        }
        let repeated = f.cardinality == Cardinality::Repeated;
        let duplicate = !repeated
            && (m.fields.contains_key(&f.name)
                || f.oneof.as_ref().is_some_and(|group| {
                    d.fields.iter().any(|candidate| {
                        candidate.oneof.as_ref() == Some(group)
                            && m.fields.contains_key(&candidate.name)
                    })
                }));
        if duplicate && context.options.duplicates == DuplicateInputPolicy::Reject {
            return Err(Error::new(
                field_start,
                "duplicate singular field rejected by policy",
            ));
        }
        let mut xs = if repeated {
            match m.fields.remove(&f.name) {
                Some(Value::Repeated(x)) => x,
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };
        if repeated
            && w == WIRE_TYPE_LENGTH_DELIMITED
            && wire(&f.kind) != WIRE_TYPE_LENGTH_DELIMITED
        {
            let length = context.length(b, &mut p)?;
            let packed = take(b, &mut p, length)?;
            let mut packed_cursor = 0;
            while packed_cursor < packed.len() {
                if xs.len() >= context.options.max_repeated_values {
                    return Err(Error::new(
                        field_start,
                        "repeated field exceeds configured value limit",
                    ));
                }
                let value = val(
                    &f.kind,
                    wire(&f.kind),
                    packed,
                    &mut packed_cursor,
                    s,
                    context,
                    depth,
                )?;
                if let (FieldType::Enum(name), Value::Enum(number)) = (&f.kind, &value)
                    && s.enums.get(name).is_some_and(|enumeration| {
                        enumeration.features.enum_type == EnumType::Closed
                            && !enumeration
                                .values
                                .iter()
                                .any(|candidate| candidate.number == *number)
                    })
                {
                    if context.options.unknown_fields == UnknownFieldPolicy::Reject {
                        return Err(Error::new(field_start, "closed enum value is unknown"));
                    }
                    if context.options.unknown_fields == UnknownFieldPolicy::Preserve {
                        let mut encoded_value = Vec::new();
                        vi(*number as i64 as u64, &mut encoded_value);
                        m.unknown_fields.push(UnknownField {
                            number: f.number,
                            wire_type: WIRE_TYPE_VARINT,
                            encoded_value,
                        });
                    }
                } else {
                    xs.push(value);
                }
            }
            m.insert(f.name.clone(), Value::Repeated(xs));
            let record = context.audit_record(
                b,
                field_start..p,
                AuditRecord {
                    tag: AuditTag::SchemaField,
                    field_name: Some(f.name.clone()),
                    field_number: n,
                    wire_type: w,
                    encoded_field: Vec::new(),
                },
            )?;
            m.audit.push(record);
            continue;
        }
        let x = field_value(f, w, b, &mut p, s, context, depth)?;
        let mut merged = false;
        if repeated {
            if xs.len() >= context.options.max_repeated_values {
                return Err(Error::new(
                    field_start,
                    "repeated field exceeds configured value limit",
                ));
            }
            xs.push(x);
            m.insert(f.name.clone(), Value::Repeated(xs));
        } else {
            if let Some(g) = &f.oneof {
                for q in &d.fields {
                    if q.oneof.as_ref() == Some(g) && q.name != f.name {
                        m.fields.remove(&q.name);
                    }
                }
            }
            merged = duplicate && matches!(x, Value::Message(_));
            match x {
                Value::Message(incoming) => {
                    if let Some(Value::Message(existing)) = m.fields.get_mut(&f.name) {
                        merge_message(existing, incoming);
                    } else {
                        m.insert(f.name.clone(), Value::Message(incoming));
                    }
                }
                value => {
                    m.insert(f.name.clone(), value);
                }
            }
        }
        if duplicate
            && !merged
            && let Some(previous) = m.audit.iter_mut().rev().find(|record| {
                let same_field = record.field_name.as_deref() == Some(&f.name);
                let same_oneof = f.oneof.as_ref().is_some_and(|group| {
                    record.field_name.as_deref().is_some_and(|name| {
                        d.field_by_name(name).and_then(|field| field.oneof.as_ref()) == Some(group)
                    })
                });
                (same_field || same_oneof)
                    && matches!(
                        record.tag,
                        AuditTag::SchemaField | AuditTag::DuplicateLastWins
                    )
            })
        {
            previous.tag = AuditTag::DuplicateDiscarded;
        }
        let tag = if repeated || !duplicate {
            AuditTag::SchemaField
        } else if merged {
            AuditTag::DuplicateMerged
        } else {
            AuditTag::DuplicateLastWins
        };
        let record = context.audit_record(
            b,
            field_start..p,
            AuditRecord {
                tag,
                field_name: Some(f.name.clone()),
                field_number: n,
                wire_type: w,
                encoded_field: Vec::new(),
            },
        )?;
        m.audit.push(record);
    }
    for f in s.fields_for(d) {
        if (f.cardinality == Cardinality::Required
            || f.features.field_presence == FieldPresence::LegacyRequired)
            && !m.fields.contains_key(&f.name)
        {
            return Err(Error::new(0, "missing required field"));
        }
    }
    Ok(m)
}
