//! Single-threaded throughput benchmark for strict wire sanitization.
//!
//! Run with `cargo bench --bench strict_throughput`.

use proto_rs::{
    AuditMode, BooleanValuePolicy, DecodeOptions, DuplicateInputPolicy, DuplicatePolicy,
    EncodeOptions, EnumValuePolicy, FieldOrder, FloatEncoding, MapOrder, Message, Result,
    UnknownFieldPolicy, Value, decode_with_options, encode_with_options, parse,
};
use std::{hint::black_box, time::Instant};

/// Iterations executed before each timed measurement.
const WARMUP_ITERATIONS: usize = 20_000;
/// Iterations executed for each reported measurement.
const MEASURED_ITERATIONS: usize = 1_000_000;
/// Number of bytes in one mebibyte for payload-throughput reporting.
const BYTES_PER_MEBIBYTE: f64 = 1024.0 * 1024.0;
/// Maximum packet bytes allowed by the benchmark's strict profile.
const MAX_PACKET_BYTES: usize = 64;
/// Maximum length-delimited payload accepted by the strict profile.
const MAX_VALUE_BYTES: usize = 16;
/// Maximum total root and synthetic map field occurrences.
const MAX_FIELD_OCCURRENCES: usize = 16;
/// Maximum entries accepted in the packet's map.
const MAX_MAP_ENTRIES: usize = 4;
/// Maximum values accepted in any repeated field.
const MAX_REPEATED_VALUES: usize = 4;
/// Maximum nested messages below the benchmark's root message.
const MAX_RECURSION_DEPTH: usize = 4;

/// Small packet whose declaration order differs from numeric field order.
const PACKET_SCHEMA: &str = r#"
    syntax = "proto3";
    package benchmark;

    message Packet {
        bool accepted = 5;
        string payload = 4;
        map<uint32, uint32> labels = 3;
        float ratio = 2;
        uint32 id = 1;
    }
"#;

/// One completed throughput measurement.
struct Measurement {
    /// Human-readable operation name.
    name: &'static str,
    /// Average elapsed nanoseconds per message.
    nanoseconds_per_message: f64,
    /// Completed messages per elapsed second.
    messages_per_second: f64,
    /// Logical input packet bytes processed per second.
    payload_mebibytes_per_second: f64,
}

/// Builds the strict decoder profile used for every decode iteration.
fn decode_options(packet_bytes: usize) -> DecodeOptions {
    DecodeOptions {
        max_message_bytes: MAX_PACKET_BYTES,
        max_recursion_depth: MAX_RECURSION_DEPTH,
        max_field_occurrences: MAX_FIELD_OCCURRENCES,
        max_length_delimited_bytes: MAX_VALUE_BYTES,
        max_repeated_values: MAX_REPEATED_VALUES,
        max_map_entries: MAX_MAP_ENTRIES,
        max_audit_bytes: packet_bytes,
        unknown_fields: UnknownFieldPolicy::Reject,
        duplicates: DuplicateInputPolicy::Reject,
        audit_mode: AuditMode::Full,
        require_minimal_varints: true,
        booleans: BooleanValuePolicy::RejectNonCanonical,
        enum_values: EnumValuePolicy::RejectUnknown,
    }
}

/// Builds the normalized, schema-only encoder profile used by the benchmark.
fn encode_options() -> EncodeOptions {
    EncodeOptions {
        forward_unknown_fields: false,
        forward_unknown_messages: false,
        forward_added_fields: false,
        duplicates: DuplicatePolicy::LastOnly,
        field_order: FieldOrder::FieldNumber,
        map_order: MapOrder::Key,
        floats: FloatEncoding::Normalize,
        max_output_bytes: MAX_PACKET_BYTES,
    }
}

/// Creates the dynamic packet used as the encoder input.
fn packet_message() -> Message {
    let mut message = Message::new();
    message.insert("accepted", Value::Bool(true));
    message.insert("payload", Value::String("ping".into()));
    message.insert(
        "labels",
        Value::Map(vec![
            (Value::Uint32(2), Value::Uint32(20)),
            (Value::Uint32(1), Value::Uint32(10)),
        ]),
    );
    message.insert("ratio", Value::Float(1.25));
    message.insert("id", Value::Uint32(150));
    message
}

/// Warms and times one fallible operation without optimizing away its result.
fn measure<T>(
    name: &'static str,
    packet_bytes: usize,
    mut operation: impl FnMut() -> Result<T>,
) -> Result<Measurement> {
    for _ in 0..WARMUP_ITERATIONS {
        black_box(operation()?);
    }
    let start = Instant::now();
    for _ in 0..MEASURED_ITERATIONS {
        black_box(operation()?);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let operations = MEASURED_ITERATIONS as f64;
    let messages_per_second = operations / elapsed;
    Ok(Measurement {
        name,
        nanoseconds_per_message: elapsed * 1_000_000_000.0 / operations,
        messages_per_second,
        payload_mebibytes_per_second: messages_per_second * packet_bytes as f64
            / BYTES_PER_MEBIBYTE,
    })
}

/// Prints one stable, machine-readable-enough benchmark result line.
fn print_measurement(measurement: &Measurement) {
    println!(
        "{:<24} {:>10.1} ns/msg  {:>12.0} msg/s  {:>9.2} MiB/s",
        measurement.name,
        measurement.nanoseconds_per_message,
        measurement.messages_per_second,
        measurement.payload_mebibytes_per_second,
    );
}

/// Constructs the descriptor once, then benchmarks only dynamic wire work.
fn main() -> Result<()> {
    let schema = parse(PACKET_SCHEMA)?;
    let Some(descriptor) = schema.message("benchmark.Packet") else {
        return Ok(());
    };
    let source_message = packet_message();
    let encoder_options = encode_options();
    let packet = encode_with_options(&schema, descriptor, &source_message, &encoder_options)?.bytes;
    let decoder_options = decode_options(packet.len());

    println!("strict sanitization benchmark");
    println!("packet size: {} bytes", packet.len());
    println!("iterations per measurement: {MEASURED_ITERATIONS}");
    println!("schema parsing: excluded");

    let decode = measure("strict decode", packet.len(), || {
        decode_with_options(&schema, descriptor, &packet, &decoder_options)
    })?;
    let encode = measure("strict encode", packet.len(), || {
        encode_with_options(&schema, descriptor, &source_message, &encoder_options)
    })?;
    let round_trip = measure("decode + encode", packet.len(), || {
        let decoded = decode_with_options(&schema, descriptor, &packet, &decoder_options)?;
        encode_with_options(&schema, descriptor, &decoded, &encoder_options)
    })?;

    print_measurement(&decode);
    print_measurement(&encode);
    print_measurement(&round_trip);
    Ok(())
}
