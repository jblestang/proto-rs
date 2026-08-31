#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! An allocation-backed, dynamically typed Protocol Buffers implementation.
//!
//! # `no_std` contract
//!
//! This library is unconditionally `#![no_std]` and only uses [`core`] and
//! [`alloc`]. It has no `std` Cargo feature and no default features. File I/O
//! is intentionally left to callers; imported schemas are supplied as source
//! strings through [`Registry`].
//!
//! Unit tests and the official conformance test adapter may use the standard
//! library, but `proto_rs` itself never does.
//!
//! # Workflow
//!
//! A caller first creates a [`Registry`] when imports are involved.
//! Every `.proto` source is registered under its logical import path.
//! Calling [`Registry::parse`] resolves the complete reachable import graph.
//! A single import-free source can instead be parsed with [`parse`].
//! The resulting [`Schema`] owns runtime message and enum descriptors.
//! Callers select a [`MessageDescriptor`] by its protobuf full name.
//! A dynamic [`Message`] is populated with named [`Value`] instances.
//! [`encode`] turns that value into protobuf binary wire bytes.
//! [`decode`] reconstructs a dynamic value using the same descriptor.
//! No generated Rust source participates in this workflow.
//!
//! # Registry example
//!
//! ```
//! use proto_rs::{Registry, Message, Value, encode};
//!
//! let mut registry = Registry::new();
//! registry.register(
//!     "model.proto",
//!     r#"syntax="proto3"; package model; message Id { uint64 value = 1; }"#,
//! );
//! registry.register(
//!     "request.proto",
//!     r#"syntax="proto3"; package api; import "model.proto";
//!        message Request { model.Id id = 1; }"#,
//! );
//! let schema = registry.parse("request.proto")?;
//! let id_descriptor = schema.message("model.Id").unwrap();
//! let request_descriptor = schema.message("api.Request").unwrap();
//! let mut id = Message::new();
//! id.insert("value", Value::Uint64(42));
//! let mut request = Message::new();
//! request.insert("id", Value::Message(id));
//! let bytes = encode(&schema, request_descriptor, &request)?;
//! assert!(!bytes.is_empty());
//! assert_eq!(id_descriptor.name, "Id");
//! # Ok::<(), proto_rs::Error>(())
//! ```
//!
//! # Audit example
//!
//! ```
//! use proto_rs::{AuditTag, EncodeOptions, DuplicatePolicy, FieldOrder, decode,
//!                encode_with_options, parse};
//!
//! let schema = parse(r#"syntax="proto3"; message A { int32 value = 1; }"#)?;
//! let descriptor = schema.message("A").unwrap();
//! let message = decode(&schema, descriptor, &[8, 1, 8, 2, 16, 3])?;
//! assert!(message.audit.iter().any(|entry| {
//!     entry.tag == AuditTag::DuplicateLastWins
//! }));
//! assert!(message.audit.iter().any(|entry| {
//!     entry.tag == AuditTag::UnknownField
//! }));
//! let output = encode_with_options(
//!     &schema,
//!     descriptor,
//!     &message,
//!     &EncodeOptions {
//!         forward_unknown_fields: false,
//!         forward_unknown_messages: false,
//!         forward_added_fields: false,
//!         duplicates: DuplicatePolicy::LastOnly,
//!         field_order: FieldOrder::FieldNumber,
//!         ..EncodeOptions::default()
//!     },
//! )?;
//! assert_eq!(output.bytes, [8, 2]);
//! # Ok::<(), proto_rs::Error>(())
//! ```
//!
//! # Compatibility
//!
//! The binary codec supports the complete exercised proto3 conformance set.
//! It also supports the ordinary, non-MessageSet proto2 binary feature set.
//! Proto2 group and extension declarations are recognized but not decoded.
//! JSON, text format, JSPB, and Editions are separate unsupported formats.
//! The repository's `CONFORMANCE.md` records the precise boundary.
//! Unsupported wire types return errors instead of being misinterpreted.
//! Unknown supported wire fields remain auditable and forwardable.
//! Serialization policy can prevent forwarding data absent from the schema.
//!
//! # Stability
//!
//! Descriptors and values are intentionally generic public data structures.
//! Audit metadata is excluded from semantic [`Message`] equality.
//! Exact encoded byte order is deterministic for a given dynamic message.
//! Protobuf semantic equivalence does not require a unique byte ordering.
//! Errors contain an owned message and the relevant byte offset.
//! APIs return [`Result`] and never require unwinding for malformed input.

extern crate alloc;
#[cfg(test)]
extern crate std;
mod codec;
mod constants;
mod json;
mod schema;
use alloc::string::String;
pub use codec::{
    AddedField, AuditMode, AuditRecord, AuditTag, BooleanValuePolicy, DecodeOptions,
    DuplicateInputPolicy, DuplicatePolicy, EncodeOptions, EncodeOutput, EnumValuePolicy,
    FieldOrder, FloatEncoding, MapOrder, Message, UnknownField, UnknownFieldPolicy, Value, decode,
    decode_with_options, encode, encode_with_options,
};
use core::fmt;
pub use json::{JsonDecodeOptions, decode_json, decode_json_with_options, encode_json};
pub use schema::{
    Cardinality, CustomOptionDescriptor, Enum, EnumType, EnumValue, ExtensionDescriptor,
    FeatureSet, Field, FieldPresence, FieldType, Import, ImportKind, JsonFormat, MessageDescriptor,
    MessageEncoding, MethodDescriptor, OneofDescriptor, OptionSetting, OptionValueKind, Registry,
    RepeatedFieldEncoding, Schema, SchemaParseOptions, ServiceDescriptor, Syntax, Utf8Validation,
    parse, parse_with_options,
};
/// Error returned when schema or wire data cannot be processed safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    /// Byte offset at which the failure became observable.
    pub offset: usize,
    /// Human-readable description of the failed validation or operation.
    pub message: String,
}
impl Error {
    /// Creates an error at the byte offset where parsing or encoding failed.
    pub(crate) fn new(offset: usize, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
        }
    }
}
impl fmt::Display for Error {
    /// Formats the diagnostic message together with its byte offset.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}
/// Result type returned by schema parsing and protobuf codec operations.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec, vec::Vec};

    const PROTO: &str = r#"
        syntax = "proto3";
        package demo;
        message Person {
          uint32 id = 1;
          string name = 2;
          repeated sint32 scores = 3;
          message Address { string city = 1; }
          Address address = 4;
        }
    "#;
    /// Deterministic randomized decoder cases executed by the normal test suite.
    const RANDOMIZED_DECODER_CASES: usize = 10_000;
    /// Largest deterministic randomized packet passed to either decoder.
    const MAX_RANDOMIZED_PACKET_BYTES: usize = 128;
    /// Initial state for the reproducible linear congruential generator.
    const RANDOMIZED_DECODER_SEED: u64 = 0x7a5d_39e1_42c6_b8f0;
    /// Full-period multiplier used by the deterministic test generator.
    const RANDOMIZED_DECODER_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
    /// Odd increment used by the deterministic test generator.
    const RANDOMIZED_DECODER_INCREMENT: u64 = 1_442_695_040_888_963_407;

    /// Verifies descriptor-driven parsing and dynamic binary round-tripping.
    #[test]
    fn parses_and_round_trips_dynamic_message() {
        let schema = parse(PROTO).unwrap();
        let descriptor = schema.message("Person").unwrap();
        let mut address = Message::new();
        address.insert("city", Value::String("Paris".to_string()));
        let mut person = Message::new();
        person.insert("id", Value::Uint32(42));
        person.insert("name", Value::String("Ada".to_string()));
        person.insert(
            "scores",
            Value::Repeated(vec![Value::Int32(-1), Value::Int32(150)]),
        );
        person.insert("address", Value::Message(address));

        let bytes = encode(&schema, descriptor, &person).unwrap();
        assert_eq!(decode(&schema, descriptor, &bytes).unwrap(), person);
    }

    /// Verifies that unknown wire occurrences survive decoding and encoding.
    #[test]
    fn preserves_unknown_fields() {
        let schema = parse(r#"syntax="proto3"; message Empty {}"#).unwrap();
        let descriptor = schema.message("Empty").unwrap();
        let bytes = [0x98, 0x06, 0x96, 0x01]; // field 99, varint 150
        let value = decode(&schema, descriptor, &bytes).unwrap();
        assert_eq!(encode(&schema, descriptor, &value).unwrap(), bytes);
    }

    /// Verifies rejection of protobuf's implementation-reserved tag range.
    #[test]
    fn rejects_reserved_field_number() {
        assert!(parse("message Bad { string x = 19000; }").is_err());
    }

    /// Verifies dynamic map encoding and protobuf's duplicate-key last-wins rule.
    #[test]
    fn maps_round_trip_and_duplicate_keys_use_last_value() {
        let schema =
            parse(r#"syntax="proto3"; message Index { map<string, int32> counts = 1; }"#).unwrap();
        let descriptor = schema.message("Index").unwrap();
        let mut message = Message::new();
        message.insert(
            "counts",
            Value::Map(vec![
                (Value::String("a".into()), Value::Int32(1)),
                (Value::String("b".into()), Value::Int32(2)),
            ]),
        );
        let encoded = encode(&schema, descriptor, &message).unwrap();
        assert_eq!(decode(&schema, descriptor, &encoded).unwrap(), message);

        // Two entries for key "a"; protobuf map semantics retain the latter.
        let duplicate = [
            0x0a, 0x05, 0x0a, 0x01, b'a', 0x10, 0x01, 0x0a, 0x05, 0x0a, 0x01, b'a', 0x10, 0x09,
        ];
        assert_eq!(
            decode(&schema, descriptor, &duplicate)
                .unwrap()
                .get("counts"),
            Some(&Value::Map(vec![(
                Value::String("a".into()),
                Value::Int32(9)
            )]))
        );
    }

    /// Verifies type resolution across transitively imported registry sources.
    #[test]
    fn resolves_transitive_cross_file_imports() {
        let mut registry = Registry::new();
        for (path, source) in [
            (
                "app.proto",
                r#"syntax="proto3"; package app; import "model.proto";
                       message Request { model.User user = 1; }"#,
            ),
            (
                "model.proto",
                r#"syntax="proto3"; package model; import "id.proto";
                       message User { ids.Id id = 1; }"#,
            ),
            (
                "id.proto",
                r#"syntax="proto3"; package ids; message Id { uint64 value = 1; }"#,
            ),
        ] {
            registry.register(path, source);
        }
        let schema = registry.parse("app.proto").unwrap();
        assert!(schema.message("app.Request").is_some());
        assert!(schema.message("model.User").is_some());
        assert!(schema.message("ids.Id").is_some());

        let request = schema.message("app.Request").unwrap();
        let mut id = Message::new();
        id.insert("value", Value::Uint64(7));
        let mut user = Message::new();
        user.insert("id", Value::Message(id));
        let mut value = Message::new();
        value.insert("user", Value::Message(user));
        let bytes = encode(&schema, request, &value).unwrap();
        assert_eq!(decode(&schema, request, &bytes).unwrap(), value);
    }

    /// Verifies weak-import tolerance and required-import failure behavior.
    #[test]
    fn permits_missing_weak_import_but_rejects_missing_normal_import() {
        let mut registry = Registry::new();
        registry.register("root.proto", "import weak \"optional.proto\"; message A {}");
        assert!(registry.parse("root.proto").is_ok());
        registry.register("root.proto", "import \"missing.proto\"; message A {}");
        assert!(registry.parse("root.proto").is_err());
    }

    /// Verifies bounds and encoded-width validation for protobuf field keys.
    #[test]
    fn rejects_out_of_range_and_overlong_field_tags() {
        let schema = parse(r#"syntax="proto3"; message A { int32 x = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        assert!(decode(&schema, descriptor, &[0x88, 0x80, 0x80, 0x80, 0x40, 1]).is_err());
        assert!(
            decode(
                &schema,
                descriptor,
                &[0x88, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 1]
            )
            .is_err()
        );
    }

    /// Verifies recursive merge semantics for repeated singular messages.
    #[test]
    fn merges_repeated_singular_message_occurrences() {
        let schema = parse(
            r#"syntax="proto3";
               message Inner { int32 a = 1; int32 b = 2; repeated int32 values = 3; }
               message Outer { Inner inner = 1; }"#,
        )
        .unwrap();
        let descriptor = schema.message("Outer").unwrap();
        let wire = [
            0x0a, 0x04, 0x08, 0x01, 0x18, 0x03, 0x0a, 0x04, 0x10, 0x02, 0x18, 0x04,
        ];
        let decoded = decode(&schema, descriptor, &wire).unwrap();
        let Some(Value::Message(inner)) = decoded.get("inner") else {
            panic!("inner message missing")
        };
        assert_eq!(inner.get("a"), Some(&Value::Int32(1)));
        assert_eq!(inner.get("b"), Some(&Value::Int32(2)));
        assert_eq!(
            inner.get("values"),
            Some(&Value::Repeated(vec![Value::Int32(3), Value::Int32(4)]))
        );
    }

    /// Verifies proto3 implicit defaults and explicit-presence serialization.
    #[test]
    fn proto3_elides_implicit_defaults_but_preserves_explicit_presence() {
        let schema = parse(
            r#"syntax="proto3"; message A {
                 int32 implicit = 1;
                 optional int32 explicit = 2;
                 oneof choice { int32 selected = 3; }
               }"#,
        )
        .unwrap();
        let descriptor = schema.message("A").unwrap();
        let mut message = Message::new();
        message.insert("implicit", Value::Int32(0));
        message.insert("explicit", Value::Int32(0));
        message.insert("selected", Value::Int32(0));
        assert_eq!(
            encode(&schema, descriptor, &message).unwrap(),
            [0x10, 0, 0x18, 0]
        );
    }

    /// Verifies audit classification and configurable forwarding policies.
    #[test]
    fn audits_and_filters_duplicates_unknowns_and_added_fields() {
        let schema = parse(r#"syntax="proto3"; message A { int32 x = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let wire = [0x08, 1, 0x08, 2, 0x10, 3, 0x1a, 1, 0xff];
        let mut message = decode(&schema, descriptor, &wire).unwrap();
        assert_eq!(
            message
                .audit
                .iter()
                .map(|record| record.tag)
                .collect::<Vec<_>>(),
            vec![
                AuditTag::DuplicateDiscarded,
                AuditTag::DuplicateLastWins,
                AuditTag::UnknownField,
                AuditTag::UnknownMessage,
            ]
        );
        message.add_field(AddedField {
            name: "application_field".into(),
            number: 4,
            wire_type: 0,
            encoded_value: vec![9],
        });

        let filtered = encode_with_options(
            &schema,
            descriptor,
            &message,
            &EncodeOptions {
                forward_unknown_fields: false,
                forward_unknown_messages: false,
                forward_added_fields: false,
                duplicates: DuplicatePolicy::LastOnly,
                field_order: FieldOrder::Declaration,
                ..EncodeOptions::default()
            },
        )
        .unwrap();
        assert_eq!(filtered.bytes, [0x08, 2]);

        let preserved = encode_with_options(
            &schema,
            descriptor,
            &message,
            &EncodeOptions {
                forward_unknown_fields: false,
                forward_unknown_messages: false,
                forward_added_fields: true,
                duplicates: DuplicatePolicy::PreserveAll,
                field_order: FieldOrder::Declaration,
                ..EncodeOptions::default()
            },
        )
        .unwrap();
        assert_eq!(preserved.bytes, [0x08, 1, 0x08, 2, 0x20, 9]);
    }

    /// Verifies numeric field ordering overrides an out-of-order declaration.
    #[test]
    fn encoder_can_order_all_occurrences_by_field_number() {
        let schema = parse(
            r#"syntax="proto3";
               message Ordered {
                 string second = 2;
                 int32 first = 1;
               }"#,
        )
        .unwrap();
        let descriptor = schema.message("Ordered").unwrap();
        let mut message = Message::new();
        message.insert("first", Value::Int32(1));
        message.insert("second", Value::String("two".into()));
        message.add_field(AddedField {
            name: "third".into(),
            number: 3,
            wire_type: 0,
            encoded_value: vec![3],
        });

        assert_eq!(
            encode(&schema, descriptor, &message).unwrap(),
            [0x12, 3, b't', b'w', b'o', 0x08, 1, 0x18, 3]
        );
        let ordered = encode_with_options(
            &schema,
            descriptor,
            &message,
            &EncodeOptions {
                field_order: FieldOrder::FieldNumber,
                ..EncodeOptions::default()
            },
        )
        .unwrap();
        assert_eq!(ordered.bytes, [0x08, 1, 0x12, 3, b't', b'w', b'o', 0x18, 3]);
    }

    /// Verifies unknown fields can be preserved, dropped with audit, or rejected.
    #[test]
    fn decode_unknown_field_policies_are_explicit() {
        let schema = parse(r#"syntax="proto3"; message A { int32 known = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let wire = [0x08, 1, 0x10, 2];

        let preserved = decode(&schema, descriptor, &wire).unwrap();
        assert_eq!(preserved.unknown_fields.len(), 1);
        let dropped = decode_with_options(
            &schema,
            descriptor,
            &wire,
            &DecodeOptions {
                unknown_fields: UnknownFieldPolicy::Drop,
                ..DecodeOptions::default()
            },
        )
        .unwrap();
        assert!(dropped.unknown_fields.is_empty());
        assert!(
            dropped
                .audit
                .iter()
                .any(|record| { record.tag == AuditTag::UnknownField && record.field_number == 2 })
        );
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &wire,
                &DecodeOptions {
                    unknown_fields: UnknownFieldPolicy::Reject,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
    }

    /// Verifies strict decoding rejects non-minimal keys, values, and lengths.
    #[test]
    fn strict_decode_rejects_every_non_minimal_varint_position() {
        let scalar_schema = parse(r#"syntax="proto3"; message A { int32 value = 1; }"#).unwrap();
        let scalar = scalar_schema.message("A").unwrap();
        let string_schema = parse(r#"syntax="proto3"; message A { string value = 1; }"#).unwrap();
        let string = string_schema.message("A").unwrap();
        let strict = DecodeOptions {
            require_minimal_varints: true,
            ..DecodeOptions::default()
        };

        assert!(decode(&scalar_schema, scalar, &[0x88, 0x00, 1]).is_ok());
        assert!(decode_with_options(&scalar_schema, scalar, &[0x88, 0x00, 1], &strict).is_err());
        assert!(decode_with_options(&scalar_schema, scalar, &[0x08, 0x81, 0x00], &strict).is_err());
        assert!(
            decode_with_options(&string_schema, string, &[0x0a, 0x81, 0x00, b'x'], &strict)
                .is_err()
        );

        let five_byte_negative_one = [0x08, 0xff, 0xff, 0xff, 0xff, 0x0f];
        assert!(decode(&scalar_schema, scalar, &five_byte_negative_one).is_ok());
        assert!(
            decode_with_options(&scalar_schema, scalar, &five_byte_negative_one, &strict).is_err()
        );
        let uint_schema = parse(r#"syntax="proto3"; message A { uint32 value = 1; }"#).unwrap();
        let uint = uint_schema.message("A").unwrap();
        let value_above_u32 = [0x08, 0x80, 0x80, 0x80, 0x80, 0x10];
        assert!(decode(&uint_schema, uint, &value_above_u32).is_ok());
        assert!(decode_with_options(&uint_schema, uint, &value_above_u32, &strict).is_err());
    }

    /// Verifies root and nested message byte limits are enforced.
    #[test]
    fn decode_enforces_message_and_length_limits() {
        let schema = parse(r#"syntax="proto3"; message A { string value = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let wire = [0x0a, 2, b'o', b'k'];
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &wire,
                &DecodeOptions {
                    max_message_bytes: wire.len() - 1,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &wire,
                &DecodeOptions {
                    max_length_delimited_bytes: 1,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
    }

    /// Verifies a 64-bit wire length cannot truncate on a 32-bit target.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn decode_rejects_lengths_that_do_not_fit_usize() {
        let schema = parse(r#"syntax="proto3"; message A { bytes value = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let length_above_u32 = [0x0a, 0x80, 0x80, 0x80, 0x80, 0x10];
        assert!(decode(&schema, descriptor, &length_above_u32).is_err());
    }

    /// Verifies recursive messages cannot exceed the configured nesting depth.
    #[test]
    fn decode_enforces_recursion_depth() {
        let schema = parse(r#"syntax="proto3"; message Node { Node child = 1; }"#).unwrap();
        let descriptor = schema.message("Node").unwrap();
        let two_nested_children = [0x0a, 2, 0x0a, 0];
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &two_nested_children,
                &DecodeOptions {
                    max_recursion_depth: 1,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
    }

    /// Verifies total field occurrences are bounded across a decode operation.
    #[test]
    fn decode_enforces_field_occurrence_limit() {
        let schema = parse(r#"syntax="proto3"; message A { repeated int32 values = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &[0x08, 1, 0x08, 2],
                &DecodeOptions {
                    max_field_occurrences: 1,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
    }

    /// Verifies repeated limits apply to both packed and unpacked encodings.
    #[test]
    fn decode_enforces_repeated_value_limit() {
        let schema = parse(r#"syntax="proto3"; message A { repeated int32 values = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let limited = DecodeOptions {
            max_repeated_values: 1,
            ..DecodeOptions::default()
        };
        assert!(decode_with_options(&schema, descriptor, &[0x08, 1, 0x08, 2], &limited).is_err());
        assert!(decode_with_options(&schema, descriptor, &[0x0a, 2, 1, 2], &limited).is_err());
    }

    /// Verifies maps cannot retain more entries than the configured limit.
    #[test]
    fn decode_enforces_map_entry_limit() {
        let schema =
            parse(r#"syntax="proto3"; message A { map<int32, int32> values = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let two_entries = [0x0a, 4, 0x08, 1, 0x10, 10, 0x0a, 4, 0x08, 2, 0x10, 20];
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &two_entries,
                &DecodeOptions {
                    max_map_entries: 1,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
    }

    /// Verifies full audit copies are bounded and metadata-only mode copies none.
    #[test]
    fn decode_bounds_or_omits_audit_bytes() {
        let schema = parse(r#"syntax="proto3"; message A { int32 value = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &[0x08, 1],
                &DecodeOptions {
                    max_audit_bytes: 1,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
        let metadata = decode_with_options(
            &schema,
            descriptor,
            &[0x08, 1],
            &DecodeOptions {
                max_audit_bytes: 0,
                audit_mode: AuditMode::MetadataOnly,
                ..DecodeOptions::default()
            },
        )
        .unwrap();
        assert_eq!(metadata.audit.len(), 1);
        assert!(metadata.audit[0].encoded_field.is_empty());
    }

    /// Verifies strict duplicate policy covers scalars, oneofs, and map keys.
    #[test]
    fn decode_can_reject_ambiguous_duplicates() {
        let scalar_schema = parse(r#"syntax="proto3"; message A { int32 value = 1; }"#).unwrap();
        let scalar = scalar_schema.message("A").unwrap();
        let oneof_schema =
            parse(r#"syntax="proto3"; message A { oneof choice { int32 a = 1; int32 b = 2; } }"#)
                .unwrap();
        let oneof = oneof_schema.message("A").unwrap();
        let map_schema =
            parse(r#"syntax="proto3"; message A { map<int32, int32> values = 1; }"#).unwrap();
        let map = map_schema.message("A").unwrap();
        let strict = DecodeOptions {
            duplicates: DuplicateInputPolicy::Reject,
            ..DecodeOptions::default()
        };

        assert!(decode_with_options(&scalar_schema, scalar, &[0x08, 1, 0x08, 2], &strict).is_err());
        assert!(decode_with_options(&oneof_schema, oneof, &[0x08, 1, 0x10, 2], &strict).is_err());
        assert!(
            decode_with_options(
                &map_schema,
                map,
                &[0x0a, 4, 0x08, 1, 0x10, 10, 0x0a, 4, 0x08, 1, 0x10, 20],
                &strict,
            )
            .is_err()
        );
        let duplicate_inside_one_entry = [0x0a, 6, 0x08, 1, 0x08, 2, 0x10, 10];
        assert!(
            decode_with_options(&map_schema, map, &duplicate_inside_one_entry, &strict,).is_err()
        );
    }

    /// Verifies every displaced scalar occurrence has an accurate final tag.
    #[test]
    fn audit_demotes_each_previous_duplicate_winner() {
        let schema = parse(r#"syntax="proto3"; message A { int32 value = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let message = decode(&schema, descriptor, &[0x08, 1, 0x08, 2, 0x08, 3]).unwrap();
        assert_eq!(
            message
                .audit
                .iter()
                .map(|record| record.tag)
                .collect::<Vec<_>>(),
            vec![
                AuditTag::DuplicateDiscarded,
                AuditTag::DuplicateDiscarded,
                AuditTag::DuplicateLastWins,
            ]
        );
    }

    /// Verifies strict scalar policies reject noncanonical bools and unknown enums.
    #[test]
    fn decode_can_reject_noncanonical_boolean_and_unknown_enum_values() {
        let schema = parse(
            r#"syntax="proto3";
               enum State { STATE_UNSPECIFIED = 0; STATE_READY = 1; }
               message A { bool enabled = 1; State state = 2; }"#,
        )
        .unwrap();
        let descriptor = schema.message("A").unwrap();
        assert!(decode(&schema, descriptor, &[0x08, 2, 0x10, 9]).is_ok());
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &[0x08, 2],
                &DecodeOptions {
                    booleans: BooleanValuePolicy::RejectNonCanonical,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
        assert!(
            decode_with_options(
                &schema,
                descriptor,
                &[0x10, 9],
                &DecodeOptions {
                    enum_values: EnumValuePolicy::RejectUnknown,
                    ..DecodeOptions::default()
                },
            )
            .is_err()
        );
    }

    /// Verifies raw duplicate replay fails when metadata-only audit discarded it.
    #[test]
    fn metadata_only_audit_cannot_preserve_displaced_wire_bytes() {
        let schema = parse(r#"syntax="proto3"; message A { int32 value = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let message = decode_with_options(
            &schema,
            descriptor,
            &[0x08, 1, 0x08, 2],
            &DecodeOptions {
                audit_mode: AuditMode::MetadataOnly,
                ..DecodeOptions::default()
            },
        )
        .unwrap();
        assert!(
            encode_with_options(
                &schema,
                descriptor,
                &message,
                &EncodeOptions {
                    duplicates: DuplicatePolicy::PreserveAll,
                    ..EncodeOptions::default()
                },
            )
            .is_err()
        );
    }

    /// Verifies map-key ordering is independent of insertion order when selected.
    #[test]
    fn encoder_can_sort_map_entries_by_key() {
        let schema =
            parse(r#"syntax="proto3"; message A { map<int32, int32> values = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let mut message = Message::new();
        message.insert(
            "values",
            Value::Map(vec![
                (Value::Int32(2), Value::Int32(20)),
                (Value::Int32(1), Value::Int32(10)),
            ]),
        );
        let ordered = encode_with_options(
            &schema,
            descriptor,
            &message,
            &EncodeOptions {
                map_order: MapOrder::Key,
                ..EncodeOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            ordered.bytes,
            [0x0a, 4, 0x08, 1, 0x10, 10, 0x0a, 4, 0x08, 2, 0x10, 20]
        );
    }

    /// Verifies float normalization removes NaN payload and signed-zero variance.
    #[test]
    fn encoder_can_normalize_floating_point_bits() {
        let schema =
            parse(r#"syntax="proto3"; message A { optional float f = 1; optional double d = 2; }"#)
                .unwrap();
        let descriptor = schema.message("A").unwrap();
        let options = EncodeOptions {
            floats: FloatEncoding::Normalize,
            ..EncodeOptions::default()
        };
        let mut first = Message::new();
        first.insert("f", Value::Float(f32::from_bits(0x7fc0_0001)));
        first.insert("d", Value::Double(-0.0));
        let mut second = Message::new();
        second.insert("f", Value::Float(f32::from_bits(0x7fff_ffff)));
        second.insert("d", Value::Double(0.0));

        assert_eq!(
            encode_with_options(&schema, descriptor, &first, &options)
                .unwrap()
                .bytes,
            encode_with_options(&schema, descriptor, &second, &options)
                .unwrap()
                .bytes
        );
    }

    /// Verifies the encoder refuses output above its configured byte budget.
    #[test]
    fn encoder_enforces_output_size_limit() {
        let schema = parse(r#"syntax="proto3"; message A { int32 value = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let mut message = Message::new();
        message.insert("value", Value::Int32(1));
        assert!(
            encode_with_options(
                &schema,
                descriptor,
                &message,
                &EncodeOptions {
                    max_output_bytes: 1,
                    ..EncodeOptions::default()
                },
            )
            .is_err()
        );
    }

    /// Verifies supported proto2 parsing, defaults, packing, and group skipping.
    #[test]
    fn parses_and_encodes_basic_proto2_with_defaults_and_groups_declared() {
        let schema = parse(
            r#"syntax="proto2";
               message Legacy {
                 required int32 id = 1 [default = -1];
                 optional string name = 2 [default = "unknown"];
                 repeated uint64 values = 3 [packed = true];
                 optional group IgnoredLegacyGroup = 4 { optional int32 x = 5; }
               }"#,
        )
        .unwrap();
        let descriptor = schema.message("Legacy").unwrap();
        assert_eq!(
            descriptor.field_by_name("id").unwrap().default.as_deref(),
            Some("-1")
        );
        assert_eq!(
            descriptor.field_by_name("name").unwrap().default.as_deref(),
            Some("unknown")
        );
        let mut message = Message::new();
        message.insert("id", Value::Int32(7));
        message.insert(
            "values",
            Value::Repeated(vec![Value::Uint64(1), Value::Uint64(300)]),
        );
        let bytes = encode(&schema, descriptor, &message).unwrap();
        assert_eq!(decode(&schema, descriptor, &bytes).unwrap(), message);
    }

    /// Verifies representative malformed schemas and wire inputs return errors
    /// rather than unwinding through the public parser and decoder APIs.
    #[test]
    fn malformed_inputs_do_not_panic() {
        let malformed_schemas = [
            "/*",
            "message A {",
            "enum A { VALUE = 0 [deprecated = true",
            "syntax = \"unknown\";",
            "message A { bytes value = 536870912; }",
        ];
        for source in malformed_schemas {
            assert!(std::panic::catch_unwind(|| parse(source)).is_ok());
        }

        let schema = parse(r#"syntax="proto3"; message A { fixed64 value = 1; }"#).unwrap();
        let descriptor = schema.message("A").unwrap();
        let malformed_wire = [
            &[][..],
            &[0x08][..],
            &[0x09, 0, 0, 0][..],
            &[0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f][..],
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02][..],
        ];
        for bytes in malformed_wire {
            assert!(std::panic::catch_unwind(|| decode(&schema, descriptor, bytes)).is_ok());
        }

        let exhaustive_short_inputs = std::panic::catch_unwind(|| {
            for first in u8::MIN..=u8::MAX {
                let _ = decode(&schema, descriptor, &[first]);
                for second in u8::MIN..=u8::MAX {
                    let _ = decode(&schema, descriptor, &[first, second]);
                }
            }
        });
        assert!(exhaustive_short_inputs.is_ok());

        let strict_short_inputs = std::panic::catch_unwind(|| {
            let strict = DecodeOptions {
                max_message_bytes: 2,
                max_recursion_depth: 2,
                max_field_occurrences: 2,
                max_length_delimited_bytes: 2,
                max_repeated_values: 2,
                max_map_entries: 2,
                max_audit_bytes: 2,
                unknown_fields: UnknownFieldPolicy::Drop,
                duplicates: DuplicateInputPolicy::Reject,
                audit_mode: AuditMode::MetadataOnly,
                require_minimal_varints: true,
                booleans: BooleanValuePolicy::RejectNonCanonical,
                enum_values: EnumValuePolicy::RejectUnknown,
            };
            for byte in u8::MIN..=u8::MAX {
                let _ = decode_with_options(&schema, descriptor, &[byte], &strict);
            }
        });
        assert!(strict_short_inputs.is_ok());
    }

    /// Runs a reproducible random corpus through compatibility and strict paths.
    #[test]
    fn randomized_decoder_smoke_corpus_does_not_panic() {
        let schema = parse(
            r#"syntax="proto3";
               enum Mode { MODE_UNSPECIFIED = 0; MODE_ACTIVE = 1; }
               message Child { string name = 1; bytes data = 2; }
               message Packet {
                 uint64 id = 1;
                 repeated sint32 samples = 2;
                 map<string, uint32> counters = 3;
                 oneof choice { bool enabled = 4; Child child = 5; }
                 Mode mode = 6;
               }"#,
        )
        .unwrap();
        let descriptor = schema.message("Packet").unwrap();
        let strict = DecodeOptions {
            max_message_bytes: MAX_RANDOMIZED_PACKET_BYTES,
            max_recursion_depth: 8,
            max_field_occurrences: 64,
            max_length_delimited_bytes: 64,
            max_repeated_values: 32,
            max_map_entries: 16,
            max_audit_bytes: 256,
            unknown_fields: UnknownFieldPolicy::Drop,
            duplicates: DuplicateInputPolicy::Reject,
            audit_mode: AuditMode::MetadataOnly,
            require_minimal_varints: true,
            booleans: BooleanValuePolicy::RejectNonCanonical,
            enum_values: EnumValuePolicy::RejectUnknown,
        };
        let encoder = EncodeOptions {
            forward_unknown_fields: false,
            forward_unknown_messages: false,
            forward_added_fields: false,
            duplicates: DuplicatePolicy::LastOnly,
            field_order: FieldOrder::FieldNumber,
            map_order: MapOrder::Key,
            floats: FloatEncoding::Normalize,
            max_output_bytes: 256,
        };

        let result = std::panic::catch_unwind(|| {
            let mut state = RANDOMIZED_DECODER_SEED;
            let mut bytes = [0; MAX_RANDOMIZED_PACKET_BYTES];
            for _ in 0..RANDOMIZED_DECODER_CASES {
                state = state
                    .wrapping_mul(RANDOMIZED_DECODER_MULTIPLIER)
                    .wrapping_add(RANDOMIZED_DECODER_INCREMENT);
                let length = state as usize % (MAX_RANDOMIZED_PACKET_BYTES + 1);
                for byte in &mut bytes[..length] {
                    state = state
                        .wrapping_mul(RANDOMIZED_DECODER_MULTIPLIER)
                        .wrapping_add(RANDOMIZED_DECODER_INCREMENT);
                    *byte = state as u8;
                }
                let packet = &bytes[..length];
                if let Ok(message) = decode(&schema, descriptor, packet) {
                    let _ = encode(&schema, descriptor, &message);
                }
                if let Ok(message) = decode_with_options(&schema, descriptor, packet, &strict) {
                    let _ = encode_with_options(&schema, descriptor, &message, &encoder);
                }
            }
        });
        assert!(result.is_ok());
    }

    /// Verifies syntactic and semantic protobuf schema invariants are enforced.
    #[test]
    fn rejects_structurally_or_semantically_invalid_schemas() {
        let invalid = [
            r#"syntax="proto3"; message A { int32 a = 1; int32 b = 1; }"#,
            r#"syntax="proto3"; message A { int32 a = 1; string a = 2; }"#,
            r#"syntax="proto3"; message A { int32 foo_bar = 1; string fooBar = 2; }"#,
            r#"syntax="proto3"; message A {
                 int32 first = 1 [json_name="value"];
                 string second = 2 [json_name="value"]; }"#,
            r#"syntax="proto3"; message A { reserved 1; int32 a = 1; }"#,
            r#"syntax="proto3"; message A { reserved "a"; int32 a = 1; }"#,
            r#"syntax="proto2"; message A { int32 a = 1; }"#,
            r#"syntax="proto3"; message A { required int32 a = 1; }"#,
            r#"syntax="proto3"; message A { int32 a = 1 [default = 1]; }"#,
            r#"syntax="proto3"; message A { repeated map<string, int32> a = 1; }"#,
            r#"syntax="proto3"; message A { oneof x { map<string, int32> a = 1; } }"#,
            r#"syntax="proto3"; message A { int32 a = 1 [packed = true]; }"#,
            r#"syntax="proto3"; enum E { ONE = 1; }"#,
            r#"syntax="proto3"; enum E { ZERO = 0; OTHER = 0; }"#,
            r#"syntax="proto3"; enum E { ZERO = 0; BIG = 2147483648; }"#,
            r#"syntax="proto3"; message A {} enum A { ZERO = 0; }"#,
            r#"syntax="proto3"; message A { message child {} int32 child = 1; }"#,
            r#"message A {} syntax="proto3";"#,
            r#"syntax="proto3"; package a; package b; message A {}"#,
            r#"syntax="proto3"; package a..b; message A {}"#,
            r#"syntax="proto3"; nonsense Thing {};"#,
            r#"syntax="proto3"; message A { reserved 1 to 3, 3 to 5; }"#,
            r#"syntax="proto3"; message A { oneof x { int32 a = 1; } int32 x = 2; }"#,
            r#"syntax="proto3"; message B {} message A { repeated B b = 1 [packed=true]; }"#,
            r#"syntax="proto2"; message B {} message A { optional B b = 1 [default=x]; }"#,
            r#"syntax="proto2"; message A { optional string a = 1 [default="\q"]; }"#,
            r#"syntax="proto2"; message A { optional string a = 1 [default="\uD800"]; }"#,
            r#"syntax="proto3"; service S { rpc Broken Request returns (Response); }"#,
            r#"syntax="proto3"; option = true; message A {}"#,
            r#"syntax="proto3"; message A { int32 invalid_octal = 08; }"#,
        ];
        for source in invalid {
            assert!(
                parse(source).is_err(),
                "schema unexpectedly accepted: {source}"
            );
        }
    }

    /// Verifies valid aliases, reservations, maps, oneofs, and packing coexist.
    #[test]
    fn accepts_semantically_valid_schema_features() {
        let schema = parse(
            r#"syntax = "proto3";
               package valid;
               option java_package = "valid.\"escaped";
               enum State {
                 option allow_alias = true;
                 STATE_UNSPECIFIED = 0;
                 STATE_READY = 1;
                 STATE_READY_ALIAS = 1;
               }
               message Example {
                 reserved 2, 4 to 6;
                 reserved "removed";
                 oneof choice { string name = 1; State state = 3; }
                 repeated State history = 7 [packed = true];
                 map<string, int32> counts = 8;
               }
               message Escaped {
                 optional string text = 01;
               }"#,
        )
        .unwrap();
        let service_schema = parse(
            r#"syntax="proto3";
               message Request {}
               message Response {}
               service Api {
                 rpc Call(stream Request) returns (stream Response);
               }"#,
        )
        .unwrap();
        assert!(service_schema.message("Request").is_some());
        assert!(schema.message("valid.Example").is_some());
    }

    /// Verifies normal transitive imports do not leak types, while public
    /// imports deliberately re-export their declarations.
    #[test]
    fn enforces_import_visibility() {
        let mut registry = Registry::new();
        registry.register(
            "common.proto",
            r#"syntax="proto3"; package common; message Hidden {}"#,
        );
        registry.register(
            "middle.proto",
            r#"syntax="proto3"; import "common.proto"; message Middle {}"#,
        );
        registry.register(
            "root.proto",
            r#"syntax="proto3"; import "middle.proto"; message Root { common.Hidden value = 1; }"#,
        );
        assert!(registry.parse("root.proto").is_err());

        registry.register(
            "middle.proto",
            r#"syntax="proto3"; import public "common.proto"; message Middle {}"#,
        );
        assert!(registry.parse("root.proto").is_ok());
    }

    /// Unknown legacy groups remain auditable and round-trip without interpretation.
    #[test]
    fn preserves_unknown_wire_groups_and_rejects_malformed_groups() {
        let schema = parse(r#"syntax="proto3"; message Empty {}"#).unwrap();
        let descriptor = schema.message("Empty").unwrap();
        let group = [0x53, 0x08, 0x07, 0x54];
        let message = decode(&schema, descriptor, &group).unwrap();
        assert!(
            message.audit.iter().any(|record| {
                record.tag == AuditTag::UnknownMessage && record.field_number == 10
            })
        );
        assert_eq!(encode(&schema, descriptor, &message).unwrap(), group);
        assert!(decode(&schema, descriptor, &[0x53, 0x08, 0x07]).is_err());
        assert!(decode(&schema, descriptor, &[0x53, 0x5c]).is_err());
        assert!(decode(&schema, descriptor, &[0x54]).is_err());

        let nested_schema = parse(
            r#"syntax="proto2";
               message MessageSetLike { extensions 4 to max; }
               message Outer { optional MessageSetLike value = 500; }"#,
        )
        .unwrap();
        let outer = nested_schema.message("Outer").unwrap();
        let message_set = [
            0xa2, 0x1f, 0x0b, 0x0b, 0x10, 0x90, 0xb3, 0xfc, 0x01, 0x1a, 0x02, 0x48, 0x63, 0x0c,
        ];
        let message = decode(&nested_schema, outer, &message_set).unwrap();
        assert_eq!(
            encode(&nested_schema, outer, &message).unwrap(),
            message_set
        );
    }

    /// Proto3 rejects legacy declarations while retaining custom-option extensions.
    #[test]
    fn enforces_proto3_group_and_extension_rules() {
        let invalid = [
            r#"syntax="proto3"; message A { optional group G = 1 {} }"#,
            r#"syntax="proto3"; message A { extensions 100 to 200; }"#,
            r#"syntax="proto3"; message A {} extend A { optional int32 x = 100; }"#,
        ];
        for source in invalid {
            assert!(
                parse(source).is_err(),
                "schema unexpectedly accepted: {source}"
            );
        }
    }

    /// Services preserve streaming and method metadata and require message endpoints.
    #[test]
    fn resolves_and_validates_proto3_services() {
        let schema = parse(
            r#"syntax="proto3"; package api;
               message Request {} message Response {}
               service Gateway {
                 option deprecated = true;
                 rpc Exchange(stream Request) returns (stream Response) {
                   option idempotency_level = IDEMPOTENT;
                 }
               }"#,
        )
        .unwrap();
        let service = schema.service("Gateway").unwrap();
        let method = &service.methods[0];
        assert_eq!(method.input_type, "api.Request");
        assert_eq!(method.output_type, "api.Response");
        assert!(method.client_streaming && method.server_streaming);
        assert_eq!(method.options[0].name, "idempotency_level");

        assert!(
            parse(
                r#"syntax="proto3"; enum E { ZERO = 0; }
               message R {} service S { rpc Bad(E) returns (R); }"#,
            )
            .is_err()
        );
        assert!(
            parse(
                r#"syntax="proto3"; message R {}
               service S { rpc Same(R) returns (R); rpc Same(R) returns (R); }"#,
            )
            .is_err()
        );
    }

    /// Built-in and custom options are retained only after semantic validation.
    #[test]
    fn resolves_and_validates_proto3_custom_options() {
        const DESCRIPTOR_OPTIONS: &str = r#"syntax="proto2"; package google.protobuf;
               message MessageOptions { extensions 1000 to max; }
               message FieldOptions { extensions 1000 to max; }"#;
        let mut registry = Registry::new();
        registry.register("google/protobuf/descriptor.proto", DESCRIPTOR_OPTIONS);
        registry.register(
            "options.proto",
            r#"syntax="proto3"; package audit;
               import "google/protobuf/descriptor.proto";
               message Metadata { string label = 1; }
               extend google.protobuf.MessageOptions {
                 Metadata annotation = 50001;
               }
               extend google.protobuf.FieldOptions {
                 bool sensitive = 50002;
                 repeated string labels = 50003;
               }
               message Record {
                 option (annotation) = { label: "important" };
                 string value = 1 [(sensitive) = true, (labels) = "one", (labels) = "two"];
               }"#,
        );
        let schema = registry.parse("options.proto").unwrap();
        assert_eq!(schema.custom_options.len(), 3);
        let record = schema.message("audit.Record").unwrap();
        assert_eq!(record.options[0].name, "(annotation)");
        assert_eq!(record.fields[0].options.len(), 3);

        let mut imported = Registry::new();
        imported.register("google/protobuf/descriptor.proto", DESCRIPTOR_OPTIONS);
        imported.register(
            "declared_options.proto",
            r#"syntax="proto3"; package audit;
               import "google/protobuf/descriptor.proto";
               message Metadata { string label = 1; }
               extend google.protobuf.MessageOptions { Metadata annotation = 50001; }"#,
        );
        imported.register(
            "consumer.proto",
            r#"syntax="proto3"; package consumer;
               import "declared_options.proto";
               message Event { option (audit.annotation).label = "external"; }"#,
        );
        let imported_schema = imported.parse("consumer.proto").unwrap();
        assert_eq!(
            imported_schema.message("consumer.Event").unwrap().options[0].name,
            "(audit.annotation).label"
        );

        let invalid_builtin = [
            r#"syntax="proto3"; message A { option unknown = true; }"#,
            r#"syntax="proto3"; option packed = true; message A {}"#,
            r#"syntax="proto3"; message A { option (missing) = true; }"#,
        ];
        for source in invalid_builtin {
            assert!(
                parse(source).is_err(),
                "schema unexpectedly accepted: {source}"
            );
        }

        let invalid_custom = [
            r#"syntax="proto3"; package p; import "google/protobuf/descriptor.proto";
               extend google.protobuf.FieldOptions { bool flag = 50001; }
               message A { option (flag) = true; }"#,
            r#"syntax="proto3"; package p; import "google/protobuf/descriptor.proto";
               extend google.protobuf.FieldOptions { bool flag = 50001; }
               message A { string x = 1 [(flag) = "yes"]; }"#,
            r#"syntax="proto3"; package p; import "google/protobuf/descriptor.proto";
               extend google.protobuf.FieldOptions { bool reserved_number = 999; }"#,
        ];
        for source in invalid_custom {
            let mut registry = Registry::new();
            registry.register("google/protobuf/descriptor.proto", DESCRIPTOR_OPTIONS);
            registry.register("invalid.proto", source);
            assert!(
                registry.parse("invalid.proto").is_err(),
                "schema unexpectedly accepted: {source}"
            );
        }
    }

    /// Verifies Edition 2023 declarations expose their official defaults.
    #[test]
    fn parses_edition_2023_defaults() {
        let schema = parse(
            r#"edition = "2023";
               message Packet { int32 id = 1; repeated uint32 samples = 2; }"#,
        )
        .unwrap();
        assert_eq!(schema.syntax, Syntax::Edition2023);
        assert_eq!(schema.features.field_presence, FieldPresence::Explicit);
        let packet = schema.message("Packet").unwrap();
        assert!(packet.field_by_name("id").unwrap().explicit_presence);
        assert_eq!(packet.field_by_name("samples").unwrap().packed, Some(true));
    }

    /// Verifies inherited Edition features affect field wire metadata.
    #[test]
    fn resolves_edition_2023_feature_overrides() {
        let schema = parse(
            r#"edition = "2023";
               option features.field_presence = IMPLICIT;
               message Packet {
                 repeated uint32 samples = 1
                   [features.repeated_field_encoding = EXPANDED];
                 int32 count = 2 [features.field_presence = EXPLICIT];
               }"#,
        )
        .unwrap();
        let packet = schema.message("Packet").unwrap();
        assert_eq!(packet.features.field_presence, FieldPresence::Implicit);
        assert_eq!(packet.field_by_name("samples").unwrap().packed, Some(false));
        assert!(packet.field_by_name("count").unwrap().explicit_presence);
    }

    /// Verifies Editions reject labels removed from the language grammar.
    #[test]
    fn rejects_labels_in_edition_2023() {
        for label in ["optional", "required"] {
            let source =
                alloc::format!("edition = \"2023\"; message Packet {{ {label} int32 id = 1; }}");
            assert!(parse(&source).is_err());
        }
    }

    /// Verifies Edition feature settings cannot alter proto3 source semantics.
    #[test]
    fn rejects_editions_features_in_proto3() {
        assert!(
            parse(
                r#"syntax = "proto3";
                   option features.field_presence = EXPLICIT;
                   message Packet {}"#
            )
            .is_err()
        );
    }

    /// Verifies DELIMITED known messages use matching group tags and round trip.
    #[test]
    fn edition_delimited_messages_round_trip() {
        let schema = parse(
            r#"edition = "2023";
               message Child { int32 value = 1; }
               message Parent {
                 Child child = 2 [features.message_encoding = DELIMITED];
               }"#,
        )
        .unwrap();
        let parent = schema.message("Parent").unwrap();
        let mut child = Message::new();
        child.insert("value", Value::Int32(7));
        let mut message = Message::new();
        message.insert("child", Value::Message(child));
        let bytes = encode(&schema, parent, &message).unwrap();
        assert_eq!(bytes, [0x13, 0x08, 0x07, 0x14]);
        assert_eq!(decode(&schema, parent, &bytes).unwrap(), message);
    }

    /// Verifies LEGACY_REQUIRED is enforced during both decode and encode.
    #[test]
    fn edition_legacy_required_is_enforced() {
        let schema = parse(
            r#"edition = "2023";
               message Packet {
                 int32 id = 1 [features.field_presence = LEGACY_REQUIRED];
               }"#,
        )
        .unwrap();
        let packet = schema.message("Packet").unwrap();
        assert!(decode(&schema, packet, &[]).is_err());
        assert!(encode(&schema, packet, &Message::new()).is_err());
    }

    /// Verifies UTF-8 NONE preserves arbitrary string bytes losslessly.
    #[test]
    fn edition_unverified_strings_round_trip() {
        let schema = parse(
            r#"edition = "2023";
               message Packet {
                 string text = 1 [features.utf8_validation = NONE];
               }"#,
        )
        .unwrap();
        let packet = schema.message("Packet").unwrap();
        let bytes = [0x0a, 0x02, 0xff, 0xfe];
        let decoded = decode(&schema, packet, &bytes).unwrap();
        assert_eq!(
            decoded.get("text"),
            Some(&Value::RawString(vec![0xff, 0xfe]))
        );
        assert_eq!(encode(&schema, packet, &decoded).unwrap(), bytes);
    }

    /// Verifies closed enum unknown numbers move to the unknown-field set.
    #[test]
    fn edition_closed_enum_values_are_unknown_fields() {
        let schema = parse(
            r#"edition = "2023";
               enum State {
                 option features.enum_type = CLOSED;
                 ZERO = 0;
               }
               message Packet { State state = 1; }"#,
        )
        .unwrap();
        let packet = schema.message("Packet").unwrap();
        let decoded = decode(&schema, packet, &[0x08, 0x07]).unwrap();
        assert!(decoded.get("state").is_none());
        assert_eq!(decoded.unknown_fields.len(), 1);
        assert_eq!(encode(&schema, packet, &decoded).unwrap(), [0x08, 0x07]);
    }

    /// Verifies descriptor-driven protobuf JSON scalar, enum, repeated, and map mappings.
    #[test]
    fn protobuf_json_round_trip() {
        let schema = parse(
            r#"syntax = "proto3";
               enum State { ZERO = 0; READY = 1; }
               message Packet {
                 int64 sequence_id = 1;
                 bytes body = 2;
                 State state = 3;
                 repeated uint32 samples = 4;
                 map<string, int32> counts = 5;
               }"#,
        )
        .unwrap();
        let packet = schema.message("Packet").unwrap();
        let json = r#"{
          "sequenceId":"9007199254740993",
          "body":"AQI=",
          "state":"READY",
          "samples":[1,2],
          "counts":{"ok":3}
        }"#;
        let message = decode_json(&schema, packet, json).unwrap();
        assert_eq!(
            message.get("sequence_id"),
            Some(&Value::Int64(9_007_199_254_740_993))
        );
        assert_eq!(message.get("body"), Some(&Value::Bytes(vec![1, 2])));
        let encoded = encode_json(&schema, packet, &message).unwrap();
        let reparsed = decode_json(&schema, packet, &encoded).unwrap();
        assert_eq!(reparsed, message);
    }

    /// Verifies typed extensions resolve, participate in the codec, and obey ranges.
    #[test]
    fn typed_extensions_are_semantically_validated() {
        let schema = parse(
            r#"edition = "2023";
               message Packet { extensions 100 to 199; }
               extend Packet { int32 audit_code = 100; }"#,
        )
        .unwrap();
        let packet = schema.message("Packet").unwrap();
        let mut message = Message::new();
        message.insert("audit_code", Value::Int32(7));
        let bytes = encode(&schema, packet, &message).unwrap();
        assert_eq!(decode(&schema, packet, &bytes).unwrap(), message);

        assert!(
            parse(
                r#"edition = "2023";
                   message Packet { extensions 100 to 199; }
                   extend Packet { int32 outside = 200; }"#
            )
            .is_err()
        );
        assert!(
            parse(
                r#"edition = "2023";
                   message Packet { int32 regular = 100; extensions 100 to 199; }
                   extend Packet { int32 collision = 100; }"#
            )
            .is_err()
        );
    }

    /// Verifies duplicate JSON names and malformed well-known values are rejected.
    #[test]
    fn protobuf_json_semantics_reject_invalid_inputs() {
        let schema = parse(r#"syntax = "proto3"; message Packet { int32 value = 1; }"#).unwrap();
        let packet = schema.message("Packet").unwrap();
        assert!(decode_json(&schema, packet, r#"{"value":1,"value":2}"#).is_err());
        assert!(decode_json(&schema, packet, r#"{"unknown":1}"#).is_err());
        assert!(decode_json(&schema, packet, r#"{"value":"9223372036854775808"}"#).is_err());
    }

    /// Import cycles and proto3 references to proto2 enums are semantic errors.
    #[test]
    fn rejects_import_cycles_and_proto2_enum_references() {
        let mut registry = Registry::new();
        registry.register(
            "a.proto",
            r#"syntax="proto3"; import "b.proto"; message A {}"#,
        );
        registry.register(
            "b.proto",
            r#"syntax="proto3"; import "a.proto"; message B {}"#,
        );
        assert!(registry.parse("a.proto").is_err());

        let mut registry = Registry::new();
        registry.register(
            "legacy.proto",
            r#"syntax="proto2"; package legacy; enum State { ZERO = 0; } message Data {}"#,
        );
        registry.register(
            "root.proto",
            r#"syntax="proto3"; import "legacy.proto";
               message Invalid { legacy.State state = 1; }"#,
        );
        assert!(registry.parse("root.proto").is_err());
        registry.register(
            "root.proto",
            r#"syntax="proto3"; import "legacy.proto";
               message Valid { legacy.Data data = 1; }"#,
        );
        assert!(registry.parse("root.proto").is_ok());
    }

    /// Public raw fields cannot smuggle additional wire occurrences.
    #[test]
    fn encoder_rejects_malformed_or_trailing_raw_field_data() {
        let schema = parse(r#"syntax="proto3"; message Packet {}"#).unwrap();
        let packet = schema.message("Packet").unwrap();
        let mut message = Message::new();
        message.add_field(AddedField {
            name: "external".into(),
            number: 1,
            wire_type: constants::WIRE_TYPE_VARINT,
            encoded_value: vec![1, 0x10, 1],
        });
        assert!(encode(&schema, packet, &message).is_err());

        message.added_fields[0].encoded_value = vec![constants::VARINT_CONTINUATION_BIT];
        assert!(encode(&schema, packet, &message).is_err());

        let mut replay = Message::new();
        replay.audit.push(AuditRecord {
            tag: AuditTag::DuplicateDiscarded,
            field_name: None,
            field_number: 1,
            wire_type: constants::WIRE_TYPE_VARINT,
            encoded_field: vec![0x08, 1, 0x10, 1],
        });
        let options = EncodeOptions {
            duplicates: DuplicatePolicy::PreserveAll,
            ..EncodeOptions::default()
        };
        assert!(encode_with_options(&schema, packet, &replay, &options).is_err());
    }

    /// Dynamic values must obey repeated, singular, oneof, and map invariants.
    #[test]
    fn encoder_rejects_semantically_inconsistent_dynamic_messages() {
        let schema = parse(
            r#"syntax="proto3";
               message Packet {
                 int32 singular = 1;
                 repeated int32 many = 2;
                 oneof choice { int32 left = 3; int32 right = 4; }
                 map<string, int32> lookup = 5;
               }"#,
        )
        .unwrap();
        let packet = schema.message("Packet").unwrap();

        let mut singular = Message::new();
        singular.insert("singular", Value::Repeated(vec![Value::Int32(1)]));
        assert!(encode(&schema, packet, &singular).is_err());

        let mut repeated = Message::new();
        repeated.insert("many", Value::Int32(1));
        assert!(encode(&schema, packet, &repeated).is_err());

        let mut oneof = Message::new();
        oneof.insert("left", Value::Int32(1));
        oneof.insert("right", Value::Int32(2));
        assert!(encode(&schema, packet, &oneof).is_err());

        let mut map = Message::new();
        map.insert(
            "lookup",
            Value::Map(vec![
                (Value::String("key".into()), Value::Int32(1)),
                (Value::String("key".into()), Value::Int32(2)),
            ]),
        );
        assert!(encode(&schema, packet, &map).is_err());
    }

    /// Closed enum descriptors reject programmatically supplied unknown values.
    #[test]
    fn encoder_rejects_unknown_closed_enum_values() {
        let schema = parse(
            r#"syntax="proto2"; enum State { ZERO = 0; } message Packet { optional State state = 1; }"#,
        )
        .unwrap();
        let packet = schema.message("Packet").unwrap();
        let mut message = Message::new();
        message.insert("state", Value::Enum(7));
        assert!(encode(&schema, packet, &message).is_err());
    }

    /// Output budgets are enforced before copying a large length-delimited value.
    #[test]
    fn encoder_preflights_large_output_appends() {
        let schema = parse(r#"syntax="proto3"; message Packet { bytes data = 1; }"#).unwrap();
        let packet = schema.message("Packet").unwrap();
        let mut message = Message::new();
        message.insert("data", Value::Bytes(vec![0; 1024]));
        let options = EncodeOptions {
            max_output_bytes: 32,
            ..EncodeOptions::default()
        };
        assert!(encode_with_options(&schema, packet, &message, &options).is_err());
    }

    /// JSON limits stop deeply nested input before semantic traversal.
    #[test]
    fn json_hardened_profile_bounds_nesting_and_input_size() {
        let schema = parse(r#"syntax="proto3"; message Packet {}"#).unwrap();
        let packet = schema.message("Packet").unwrap();
        let options = JsonDecodeOptions {
            max_nesting_depth: 2,
            max_input_bytes: 32,
            ..JsonDecodeOptions::hardened()
        };
        assert!(
            decode_json_with_options(&schema, packet, r#"{"a":{"b":{"c":0}}}"#, &options).is_err()
        );
        assert!(decode_json_with_options(&schema, packet, &" ".repeat(33), &options).is_err());
    }

    /// JSON integer conversion rejects values just beyond 64-bit boundaries.
    #[test]
    fn json_rejects_rounded_64_bit_integer_overflow() {
        let schema =
            parse(r#"syntax="proto3"; message Packet { int64 signed = 1; uint64 unsigned = 2; }"#)
                .unwrap();
        let packet = schema.message("Packet").unwrap();
        assert!(decode_json(&schema, packet, r#"{"signed":9.223372036854776e18}"#).is_err());
        assert!(decode_json(&schema, packet, r#"{"unsigned":1.8446744073709552e19}"#).is_err());
        assert!(decode_json(&schema, packet, r#"{"signed":"1.5e1"}"#).is_ok());
    }

    /// Bytes JSON rejects invalid padding and data following the padding.
    #[test]
    fn json_rejects_noncanonical_base64() {
        let schema = parse(r#"syntax="proto3"; message Packet { bytes data = 1; }"#).unwrap();
        let packet = schema.message("Packet").unwrap();
        assert!(decode_json(&schema, packet, r#"{"data":"Zg==junk"}"#).is_err());
        assert!(decode_json(&schema, packet, r#"{"data":"Zh=="}"#).is_ok());
        assert!(decode_json(&schema, packet, r#"{"data":"Zg=="}"#).is_ok());
        assert!(decode_json(&schema, packet, r#"{"data":"Zg"}"#).is_ok());
    }

    /// Proto-name and jsonName spellings still denote one logical occurrence.
    #[test]
    fn json_rejects_duplicate_field_aliases_after_implicit_default() {
        let schema = parse(r#"syntax="proto3"; message Packet { int32 foo_bar = 1; }"#).unwrap();
        let packet = schema.message("Packet").unwrap();
        assert!(decode_json(&schema, packet, r#"{"foo_bar":0,"fooBar":1}"#).is_err());
    }

    /// Timestamp JSON accepts only normalized seconds from zero through 59.
    #[test]
    fn json_rejects_leap_second_timestamp_spelling() {
        let schema = parse(
            r#"syntax="proto3"; package google.protobuf;
               message Timestamp { int64 seconds = 1; int32 nanos = 2; }"#,
        )
        .unwrap();
        let timestamp = schema.message("google.protobuf.Timestamp").unwrap();
        assert!(decode_json(&schema, timestamp, r#""2016-12-31T23:59:60Z""#).is_err());
    }

    /// Schema parsing exposes finite source, nesting, token, and graph limits.
    #[test]
    fn hardened_schema_options_bound_untrusted_registries() {
        let options = SchemaParseOptions {
            max_source_bytes: 32,
            ..SchemaParseOptions::hardened()
        };
        assert!(parse_with_options(&" ".repeat(33), &options).is_err());

        let options = SchemaParseOptions {
            max_nesting_depth: 1,
            ..SchemaParseOptions::hardened()
        };
        assert!(parse_with_options(r#"message A { message B {} }"#, &options).is_err());

        let mut registry = Registry::new();
        registry.register("root.proto", r#"import "child.proto"; message Root {}"#);
        registry.register("child.proto", "message Child {}");
        let options = SchemaParseOptions {
            max_registry_files: 1,
            ..SchemaParseOptions::hardened()
        };
        assert!(registry.parse_with_options("root.proto", &options).is_err());
    }
}
