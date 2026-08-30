//! Receives, audits, and sanitizes a dynamic protobuf message.
//!
//! Run with `cargo run --example filter_spurious_fields`.

use proto_rs::{
    AuditMode, AuditTag, BooleanValuePolicy, DecodeOptions, DuplicateInputPolicy, DuplicatePolicy,
    EncodeOptions, EnumValuePolicy, FieldOrder, Result, UnknownFieldPolicy, decode_with_options,
    encode_with_options, parse,
};

/// Maximum complete wire message accepted by this example gateway.
const MAX_MESSAGE_BYTES: usize = 4 * 1024;
/// Maximum bytes accepted in one string, bytes, message, or packed value.
const MAX_LENGTH_DELIMITED_BYTES: usize = 1024;
/// Maximum nested-message depth accepted by this example gateway.
const MAX_RECURSION_DEPTH: usize = 16;
/// Maximum total wire occurrences accepted across the message tree.
const MAX_FIELD_OCCURRENCES: usize = 64;
/// Maximum values retained by one repeated field.
const MAX_REPEATED_VALUES: usize = 32;
/// Maximum entries retained by one map field.
const MAX_MAP_ENTRIES: usize = 32;

/// Schema understood by the receiver.
const EXPECTED_SCHEMA: &str = r#"
    syntax = "proto3";
    package example;

    message Reply {
        string payload = 2;
        int32 status = 1;
    }
"#;

/// Example bytes received from an untrusted or newer sender.
///
/// They contain duplicate `status` and `payload` values, unknown varint field
/// 99, and unknown length-delimited field 100. Protobuf's singular-field rule
/// retains the last value of each expected field.
const RECEIVED_WIRE: &[u8] = &[
    0x08, 0x01, // status = 1: displaced by the later occurrence
    0x12, 0x03, b'o', b'l', b'd', // payload = "old": displaced
    0x98, 0x06, 0x07, // unknown field 99, varint value 7
    0x08, 0x02, // status = 2: retained by last-wins
    0x12, 0x02, b'o', b'k', // payload = "ok": retained by last-wins
    0xa2, 0x06, 0x03, b'n', b'e', b'w', // unknown field 100, three bytes
];

/// Reports whether an audit record describes data removed by sanitization.
fn is_spurious(tag: AuditTag) -> bool {
    matches!(
        tag,
        AuditTag::DuplicateDiscarded | AuditTag::UnknownField | AuditTag::UnknownMessage
    )
}

/// Decodes the received message, prints its audit evidence, and filters it.
fn main() -> Result<()> {
    let schema = parse(EXPECTED_SCHEMA)?;
    let Some(descriptor) = schema.message("example.Reply") else {
        // This branch cannot be reached while EXPECTED_SCHEMA remains valid,
        // but avoids relying on a panic in an executable example.
        return Ok(());
    };
    let message = decode_with_options(
        &schema,
        descriptor,
        RECEIVED_WIRE,
        &DecodeOptions {
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_recursion_depth: MAX_RECURSION_DEPTH,
            max_field_occurrences: MAX_FIELD_OCCURRENCES,
            max_length_delimited_bytes: MAX_LENGTH_DELIMITED_BYTES,
            max_repeated_values: MAX_REPEATED_VALUES,
            max_map_entries: MAX_MAP_ENTRIES,
            max_audit_bytes: RECEIVED_WIRE.len(),
            unknown_fields: UnknownFieldPolicy::Drop,
            duplicates: DuplicateInputPolicy::Allow,
            audit_mode: AuditMode::Full,
            require_minimal_varints: true,
            booleans: BooleanValuePolicy::RejectNonCanonical,
            enum_values: EnumValuePolicy::RejectUnknown,
        },
    )?;

    println!("semantic fields after decoding: {:#?}", message.fields);
    println!("\nduplicate and schema-external wire occurrences:");
    for record in &message.audit {
        if is_spurious(record.tag) || record.tag == AuditTag::DuplicateLastWins {
            println!(
                "  {:?}: name={:?}, number={}, wire_type={}, bytes={:02x?}",
                record.tag,
                record.field_name,
                record.field_number,
                record.wire_type,
                record.encoded_field,
            );
        }
    }

    let sanitized = encode_with_options(
        &schema,
        descriptor,
        &message,
        &EncodeOptions {
            forward_unknown_fields: false,
            forward_unknown_messages: false,
            forward_added_fields: false,
            duplicates: DuplicatePolicy::LastOnly,
            field_order: FieldOrder::FieldNumber,
            ..EncodeOptions::default()
        },
    )?;

    println!("\nreceived bytes:  {RECEIVED_WIRE:02x?}");
    println!("sanitized bytes: {:02x?}", sanitized.bytes);
    println!("only status=2 and payload=\"ok\" remain");
    Ok(())
}
