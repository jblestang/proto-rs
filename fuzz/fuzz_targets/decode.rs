#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_rs::{
    AuditMode, BooleanValuePolicy, DecodeOptions, DuplicateInputPolicy, DuplicatePolicy,
    EncodeOptions, EnumValuePolicy, FieldOrder, FloatEncoding, MapOrder, Schema,
    UnknownFieldPolicy, decode, decode_with_options, encode_with_options, parse,
};
use std::{hint::black_box, sync::OnceLock};

/// Maximum payload passed to compatibility or strict decoding.
const MAX_FUZZ_PAYLOAD_BYTES: usize = 4 * 1024;
/// Maximum values retained in one repeated field during fuzzing.
const MAX_REPEATED_VALUES: usize = 64;
/// Maximum entries retained in one map field during fuzzing.
const MAX_MAP_ENTRIES: usize = 64;
/// Maximum complete source bytes retained across audit records.
const MAX_AUDIT_BYTES: usize = 8 * 1024;
/// Maximum sanitized message bytes emitted after successful decoding.
const MAX_ENCODED_BYTES: usize = 8 * 1024;

/// Descriptors chosen to reach scalar, packed, map, oneof, and recursive paths.
const FUZZ_SCHEMA: &str = r#"
    syntax = "proto3";
    package fuzz;

    enum Mode {
        MODE_UNSPECIFIED = 0;
        MODE_ACTIVE = 1;
    }

    message Child {
        string name = 1;
        bytes opaque = 2;
    }

    message Packet {
        uint64 id = 1;
        string text = 2;
        bytes opaque = 3;
        repeated sint32 samples = 4;
        map<string, uint32> counters = 5;
        oneof choice {
            bool enabled = 6;
            Child child = 7;
        }
        Mode mode = 8;
        fixed64 timestamp = 9;
        double ratio = 10;
    }

    message Recursive {
        Recursive child = 1;
        bytes data = 2;
        repeated fixed32 values = 3;
    }
"#;

/// Lazily parsed schema shared by every libFuzzer iteration.
static SCHEMA: OnceLock<Option<Schema>> = OnceLock::new();

/// Chooses the unknown-field policy from two control bits.
fn unknown_policy(control: u8) -> UnknownFieldPolicy {
    match control & 0b11 {
        0 => UnknownFieldPolicy::Preserve,
        1 => UnknownFieldPolicy::Drop,
        _ => UnknownFieldPolicy::Reject,
    }
}

/// Builds bounded strict options from fuzzer-controlled policy bits.
fn strict_options(policy: u8, limits: u8) -> DecodeOptions {
    DecodeOptions {
        max_message_bytes: MAX_FUZZ_PAYLOAD_BYTES,
        max_recursion_depth: usize::from(limits & 0x0f),
        max_field_occurrences: usize::from(limits >> 4)
            .saturating_mul(16)
            .saturating_add(1),
        max_length_delimited_bytes: usize::from(limits).saturating_add(1),
        max_repeated_values: MAX_REPEATED_VALUES,
        max_map_entries: MAX_MAP_ENTRIES,
        max_audit_bytes: MAX_AUDIT_BYTES,
        unknown_fields: unknown_policy(policy),
        duplicates: if policy & 0b100 != 0 {
            DuplicateInputPolicy::Reject
        } else {
            DuplicateInputPolicy::Allow
        },
        audit_mode: if policy & 0b1000 != 0 {
            AuditMode::MetadataOnly
        } else {
            AuditMode::Full
        },
        require_minimal_varints: policy & 0b1_0000 != 0,
        booleans: if policy & 0b10_0000 != 0 {
            BooleanValuePolicy::RejectNonCanonical
        } else {
            BooleanValuePolicy::CoerceNonzero
        },
        enum_values: if policy & 0b100_0000 != 0 {
            EnumValuePolicy::RejectUnknown
        } else {
            EnumValuePolicy::Preserve
        },
    }
}

/// Sanitized encoder used to exercise successful decoded messages recursively.
fn encode_options() -> EncodeOptions {
    EncodeOptions {
        forward_unknown_fields: false,
        forward_unknown_messages: false,
        forward_added_fields: false,
        duplicates: DuplicatePolicy::LastOnly,
        field_order: FieldOrder::FieldNumber,
        map_order: MapOrder::Key,
        floats: FloatEncoding::Normalize,
        max_output_bytes: MAX_ENCODED_BYTES,
    }
}

fuzz_target!(|input: &[u8]| {
    let schema = SCHEMA.get_or_init(|| parse(FUZZ_SCHEMA).ok());
    let Some(schema) = schema.as_ref() else {
        return;
    };
    let policy = input.first().copied().unwrap_or_default();
    let limits = input.get(1).copied().unwrap_or_default();
    let payload = input.get(2..).unwrap_or_default();
    if payload.len() > MAX_FUZZ_PAYLOAD_BYTES {
        return;
    }
    let message_name = if policy & 0b1000_0000 == 0 {
        "fuzz.Packet"
    } else {
        "fuzz.Recursive"
    };
    let Some(descriptor) = schema.message(message_name) else {
        return;
    };

    if let Ok(message) = decode(schema, descriptor, payload) {
        drop(black_box(encode_with_options(
            schema,
            descriptor,
            &message,
            &encode_options(),
        )));
    }

    let options = strict_options(policy, limits);
    if let Ok(message) = decode_with_options(schema, descriptor, payload, &options) {
        drop(black_box(encode_with_options(
            schema,
            descriptor,
            &message,
            &encode_options(),
        )));
    }
});
