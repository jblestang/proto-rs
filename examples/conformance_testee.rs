//! Adapter for Google's official protobuf conformance runner.
//!
//! Usage:
//! `conformance_test_runner target/debug/examples/conformance_testee /path/to/protobuf`

use proto_rs::{
    JsonDecodeOptions, Message, Registry, Schema, Value, decode, decode_json_with_options, encode,
    encode_json,
};
use std::{
    env, fs,
    io::{self, Read, Write},
    path::Path,
};

/// Conformance protocol value used when no output format was specified.
const FORMAT_UNSPECIFIED: i32 = 0;
/// Conformance protocol value requesting protobuf binary output.
const FORMAT_PROTOBUF: i32 = 1;
/// Conformance protocol value requesting protobuf JSON output.
const FORMAT_JSON: i32 = 2;
/// Conformance protocol value requesting JavaScript protobuf output.
const FORMAT_JSPB: i32 = 3;
/// Conformance protocol value requesting protobuf text-format output.
const FORMAT_TEXT: i32 = 4;
/// Conformance category requesting unknown JSON members be ignored.
const CATEGORY_JSON_IGNORE_UNKNOWN: i32 = 3;
/// Bytes in the little-endian request and response length prefix.
const FRAME_LENGTH_SIZE: usize = core::mem::size_of::<u32>();

/// Recursively loads `.proto` sources while preserving import-relative paths.
fn collect(directory: &Path, prefix: &str, out: &mut Vec<(String, String)>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, prefix, out)?;
        } else if path.extension().and_then(|x| x.to_str()) == Some("proto") {
            let relative = path.strip_prefix(prefix).unwrap_or(&path);
            out.push((
                relative.to_string_lossy().trim_start_matches('/').into(),
                fs::read_to_string(path)?,
            ));
        }
    }
    Ok(())
}

/// Builds the conformance schema registry from the vendored protobuf tree.
fn load_schema(root: &Path) -> Result<Schema, String> {
    let mut owned = vec![(
        "conformance_root.proto".into(),
        r#"syntax = "proto3";
           import "conformance/conformance.proto";
           import "conformance/test_protos/test_messages_edition2023.proto";
           import "editions/golden/test_messages_proto2_editions.proto";
           import "editions/golden/test_messages_proto3_editions.proto";
           import "google/protobuf/test_messages_proto2.proto";
           import "google/protobuf/test_messages_proto3.proto";"#
            .into(),
    )];
    collect(
        &root.join("src"),
        root.join("src").to_str().unwrap(),
        &mut owned,
    )
    .map_err(|error| error.to_string())?;
    collect(
        root.join("conformance").as_path(),
        root.to_str().unwrap(),
        &mut owned,
    )
    .map_err(|error| error.to_string())?;
    collect(
        root.join("editions").as_path(),
        root.to_str().unwrap(),
        &mut owned,
    )
    .map_err(|error| error.to_string())?;
    let mut registry = Registry::new();
    for (path, source) in owned {
        registry.register(path, source);
    }
    registry
        .parse("conformance_root.proto")
        .map_err(|error| error.to_string())
}

/// Executes one binary conformance request and constructs its protocol response.
fn response(schema: &Schema, request_bytes: &[u8]) -> Message {
    let request_type = schema.message("conformance.ConformanceRequest").unwrap();
    let request = match decode(schema, request_type, request_bytes) {
        Ok(request) => request,
        Err(error) => return field("runtime_error", Value::String(error.to_string())),
    };
    let message_type = match request.get("message_type") {
        Some(Value::String(value)) => value.as_str(),
        _ => {
            return field(
                "runtime_error",
                Value::String("request has no message_type".into()),
            );
        }
    };
    if message_type == "conformance.FailureSet" {
        let empty = Message::new();
        let bytes = encode(
            schema,
            schema.message("conformance.FailureSet").unwrap(),
            &empty,
        )
        .unwrap();
        return field("protobuf_payload", Value::Bytes(bytes));
    }
    let requested_format = match request.get("requested_output_format") {
        Some(Value::Enum(value)) => *value,
        _ => FORMAT_UNSPECIFIED,
    };
    if request.get("text_payload").is_some() || requested_format == FORMAT_TEXT {
        return skipped("protobuf text format is not implemented");
    }
    if request.get("jspb_payload").is_some() || requested_format == FORMAT_JSPB {
        return skipped("JSPB is not implemented");
    }
    if message_type.starts_with("protobuf_test_messages.edition_unstable.") {
        return skipped("unstable protobuf Editions are not implemented");
    }
    let Some(descriptor) = schema.message(message_type) else {
        return field(
            "runtime_error",
            Value::String(format!("unexpected message type: {message_type}")),
        );
    };
    let ignore_unknown_fields = matches!(
        request.get("test_category"),
        Some(Value::Enum(CATEGORY_JSON_IGNORE_UNKNOWN))
    );
    let decoded = match request.get("protobuf_payload") {
        Some(Value::Bytes(payload)) => decode(schema, descriptor, payload),
        _ => match request.get("json_payload") {
            Some(Value::String(payload)) => decode_json_with_options(
                schema,
                descriptor,
                payload,
                &JsonDecodeOptions {
                    ignore_unknown_fields,
                },
            ),
            _ => {
                return field(
                    "runtime_error",
                    Value::String("invalid request payload".into()),
                );
            }
        },
    };
    let value = match decoded {
        Ok(value) => value,
        Err(error) => return field("parse_error", Value::String(error.to_string())),
    };
    match requested_format {
        FORMAT_PROTOBUF => match encode(schema, descriptor, &value) {
            Ok(bytes) => field("protobuf_payload", Value::Bytes(bytes)),
            Err(error) => field("serialize_error", Value::String(error.to_string())),
        },
        FORMAT_JSON => match encode_json(schema, descriptor, &value) {
            Ok(json) => field("json_payload", Value::String(json)),
            Err(error) => field("serialize_error", Value::String(error.to_string())),
        },
        _ => field(
            "runtime_error",
            Value::String("unsupported output format".into()),
        ),
    }
}

/// Constructs a conformance response that records an intentional feature skip.
fn skipped(reason: &str) -> Message {
    field("skipped", Value::String(reason.into()))
}

/// Constructs a one-field dynamic conformance response.
fn field(name: &str, value: Value) -> Message {
    let mut response = Message::new();
    response.insert(name, value);
    response
}

/// Runs the length-prefixed conformance request loop on standard I/O.
fn main() -> Result<(), String> {
    let source_root = env::args()
        .nth(1)
        .ok_or("pass the protobuf source-tree path as the first argument")?;
    let schema = load_schema(Path::new(&source_root))?;
    let response_type = schema
        .message("conformance.ConformanceResponse")
        .ok_or("conformance response descriptor missing")?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut length = [0; FRAME_LENGTH_SIZE];
        match input.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.to_string()),
        }
        let mut request = vec![0; u32::from_le_bytes(length) as usize];
        input.read_exact(&mut request).map_err(|e| e.to_string())?;
        let message = response(&schema, &request);
        let bytes = encode(&schema, response_type, &message).map_err(|e| e.to_string())?;
        output
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .and_then(|_| output.write_all(&bytes))
            .and_then(|_| output.flush())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
