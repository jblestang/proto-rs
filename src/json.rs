//! Descriptor-driven Protocol Buffers JSON mapping.
//!
//! JSON syntax is parsed into an allocation-backed tree, after which this
//! module applies protobuf field names, numeric ranges, enum names, maps,
//! repeated fields, oneofs, bytes encoding, and well-known-type rules. No
//! generated protobuf message code or standard-library I/O is involved.

use crate::{
    Cardinality, Enum, Error, FieldType, Message, MessageDescriptor, Result, Schema, Value,
    constants::{
        HARDENED_JSON_MAX_ARRAY_VALUES, HARDENED_JSON_MAX_DECODED_BYTES,
        HARDENED_JSON_MAX_INPUT_BYTES, HARDENED_JSON_MAX_NESTING_DEPTH,
        HARDENED_JSON_MAX_OBJECT_FIELDS, HARDENED_JSON_MAX_STRING_BYTES,
    },
    decode, encode,
};
use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde_json::{Map as JsonMap, Number, Value as JsonValue};

/// Controls acceptance of schema-unknown JSON object members.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonDecodeOptions {
    /// Ignore unknown members when true; reject them when false.
    pub ignore_unknown_fields: bool,
    /// Maximum UTF-8 input size accepted before JSON parsing allocates.
    pub max_input_bytes: usize,
    /// Maximum nested JSON object/array depth.
    pub max_nesting_depth: usize,
    /// Maximum members allowed in any JSON object.
    pub max_object_fields: usize,
    /// Maximum elements allowed in any JSON array.
    pub max_array_values: usize,
    /// Maximum bytes allowed in one JSON string spelling.
    pub max_string_bytes: usize,
    /// Maximum bytes produced by one protobuf bytes-field base64 value.
    pub max_decoded_bytes: usize,
}

impl Default for JsonDecodeOptions {
    fn default() -> Self {
        Self {
            ignore_unknown_fields: false,
            max_input_bytes: usize::MAX,
            max_nesting_depth: 128,
            max_object_fields: usize::MAX,
            max_array_values: usize::MAX,
            max_string_bytes: usize::MAX,
            max_decoded_bytes: usize::MAX,
        }
    }
}

impl JsonDecodeOptions {
    /// Returns finite limits suitable for parsing hostile JSON documents.
    pub const fn hardened() -> Self {
        Self {
            ignore_unknown_fields: false,
            max_input_bytes: HARDENED_JSON_MAX_INPUT_BYTES,
            max_nesting_depth: HARDENED_JSON_MAX_NESTING_DEPTH,
            max_object_fields: HARDENED_JSON_MAX_OBJECT_FIELDS,
            max_array_values: HARDENED_JSON_MAX_ARRAY_VALUES,
            max_string_bytes: HARDENED_JSON_MAX_STRING_BYTES,
            max_decoded_bytes: HARDENED_JSON_MAX_DECODED_BYTES,
        }
    }
}

/// Decodes protobuf JSON using strict unknown-field handling.
///
/// # Errors
///
/// Returns an error for invalid JSON, unknown fields, duplicate oneof members,
/// out-of-range numbers, invalid enum names, malformed base64, or a JSON shape
/// incompatible with the supplied descriptor.
pub fn decode_json(
    schema: &Schema,
    descriptor: &MessageDescriptor,
    input: &str,
) -> Result<Message> {
    decode_json_with_options(schema, descriptor, input, &JsonDecodeOptions::default())
}

/// Decodes protobuf JSON with explicit unknown-field behavior.
///
/// # Errors
///
/// Returns the same structural and semantic errors as [`decode_json`].
pub fn decode_json_with_options(
    schema: &Schema,
    descriptor: &MessageDescriptor,
    input: &str,
    options: &JsonDecodeOptions,
) -> Result<Message> {
    if input.len() > options.max_input_bytes {
        return Err(Error::new(0, "JSON input exceeds configured size limit"));
    }
    reject_duplicate_json_keys(input, options)?;
    let json: JsonValue = serde_json::from_str(input)
        .map_err(|error| Error::new(error.column(), format!("invalid JSON: {error}")))?;
    json_to_message(schema, descriptor, &json, options)
}

/// Encodes a dynamic message using the canonical protobuf JSON mapping.
///
/// # Errors
///
/// Returns an error when a dynamic value is incompatible with its descriptor,
/// contains an unknown enum number, or cannot be represented as protobuf JSON.
pub fn encode_json(
    schema: &Schema,
    descriptor: &MessageDescriptor,
    message: &Message,
) -> Result<String> {
    let json = message_to_json(schema, descriptor, message)?;
    serde_json::to_string(&json).map_err(|error| Error::new(0, error.to_string()))
}

fn json_to_message(
    schema: &Schema,
    descriptor: &MessageDescriptor,
    json: &JsonValue,
    options: &JsonDecodeOptions,
) -> Result<Message> {
    if let Some(message) = decode_well_known(schema, descriptor, json, options)? {
        return Ok(message);
    }
    let object = json
        .as_object()
        .ok_or_else(|| Error::new(0, "protobuf JSON message must be an object"))?;
    let mut message = Message::new();
    let mut seen_fields = BTreeSet::new();
    for (json_name, json_value) in object {
        let field = schema.fields_for(descriptor).find(|field| {
            field.json_name() == *json_name
                || field.name == *json_name
                || format!("[{}]", field.name) == *json_name
        });
        let Some(field) = field else {
            if options.ignore_unknown_fields {
                continue;
            }
            return Err(Error::new(0, format!("unknown JSON field: {json_name}")));
        };
        if !seen_fields.insert(field.name.as_str()) {
            return Err(Error::new(0, format!("duplicate JSON field: {json_name}")));
        }
        if options.ignore_unknown_fields && unknown_enum_name(schema, &field.kind, json_value) {
            continue;
        }
        if json_value.is_null()
            && !matches!(
                &field.kind,
                FieldType::Message(name) if name == "google.protobuf.Value"
            )
            && !matches!(
                &field.kind,
                FieldType::Enum(name) if name == "google.protobuf.NullValue"
            )
        {
            continue;
        }
        if let Some(oneof) = &field.oneof
            && descriptor.fields.iter().any(|candidate| {
                candidate.oneof.as_ref() == Some(oneof) && message.get(&candidate.name).is_some()
            })
        {
            return Err(Error::new(
                0,
                format!("multiple JSON values for oneof {oneof}"),
            ));
        }
        let value = if let FieldType::Map(key, value) = &field.kind {
            decode_map(schema, key, value, json_value, options)?
        } else if field.cardinality == Cardinality::Repeated {
            let array = json_value
                .as_array()
                .ok_or_else(|| Error::new(0, "repeated JSON field must be an array"))?;
            let mut values = Vec::with_capacity(array.len());
            for element in array {
                if element.is_null() {
                    return Err(Error::new(0, "repeated JSON element cannot be null"));
                }
                if options.ignore_unknown_fields && unknown_enum_name(schema, &field.kind, element)
                {
                    continue;
                }
                values.push(json_to_scalar(schema, &field.kind, element, options)?);
            }
            Value::Repeated(values)
        } else {
            json_to_scalar(schema, &field.kind, json_value, options)?
        };
        if field.explicit_presence || !json_is_default(&value) {
            message.insert(field.name.clone(), value);
        }
    }
    Ok(message)
}

fn json_to_scalar(
    schema: &Schema,
    kind: &FieldType,
    json: &JsonValue,
    options: &JsonDecodeOptions,
) -> Result<Value> {
    Ok(match kind {
        FieldType::Double => Value::Double(json_float(json)?),
        FieldType::Float => {
            let parsed = json_float(json)?;
            let value = parsed as f32;
            if parsed.is_finite() && !value.is_finite() {
                return Err(Error::new(0, "float JSON value out of range"));
            }
            Value::Float(value)
        }
        FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 => Value::Int32(
            integer_i64(json)?
                .try_into()
                .map_err(|_| Error::new(0, "int32 JSON value out of range"))?,
        ),
        FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => {
            Value::Int64(integer_i64(json)?)
        }
        FieldType::Uint32 | FieldType::Fixed32 => Value::Uint32(
            integer_u64(json)?
                .try_into()
                .map_err(|_| Error::new(0, "uint32 JSON value out of range"))?,
        ),
        FieldType::Uint64 | FieldType::Fixed64 => Value::Uint64(integer_u64(json)?),
        FieldType::Bool => Value::Bool(
            json.as_bool()
                .ok_or_else(|| Error::new(0, "boolean JSON field must be true or false"))?,
        ),
        FieldType::String => Value::String(
            json.as_str()
                .ok_or_else(|| Error::new(0, "string JSON field must be a string"))?
                .to_string(),
        ),
        FieldType::Bytes => Value::Bytes(base64_decode(
            json.as_str()
                .ok_or_else(|| Error::new(0, "bytes JSON field must be a string"))?,
            options.max_decoded_bytes,
        )?),
        FieldType::Enum(name) => Value::Enum(json_enum(
            schema
                .enums
                .get(name)
                .ok_or_else(|| Error::new(0, "enum descriptor missing"))?,
            json,
        )?),
        FieldType::Message(name) => Value::Message(json_to_message(
            schema,
            schema
                .message(name)
                .ok_or_else(|| Error::new(0, "message descriptor missing"))?,
            json,
            options,
        )?),
        FieldType::Map(..) => return Err(Error::new(0, "nested map type is invalid")),
    })
}

fn message_to_json(
    schema: &Schema,
    descriptor: &MessageDescriptor,
    message: &Message,
) -> Result<JsonValue> {
    if let Some(json) = encode_well_known(schema, descriptor, message)? {
        return Ok(json);
    }
    let mut object = JsonMap::new();
    for field in schema.fields_for(descriptor) {
        let Some(value) = message.get(&field.name) else {
            continue;
        };
        let json = if let FieldType::Map(key, value_kind) = &field.kind {
            encode_map(schema, key, value_kind, value)?
        } else if field.cardinality == Cardinality::Repeated {
            let Value::Repeated(values) = value else {
                return Err(Error::new(0, "repeated field has non-repeated value"));
            };
            JsonValue::Array(
                values
                    .iter()
                    .map(|value| scalar_to_json(schema, &field.kind, value))
                    .collect::<Result<Vec<_>>>()?,
            )
        } else {
            scalar_to_json(schema, &field.kind, value)?
        };
        let name = if field.name.contains('.') && descriptor.field_by_name(&field.name).is_none() {
            format!("[{}]", field.name)
        } else {
            field.json_name()
        };
        object.insert(name, json);
    }
    Ok(JsonValue::Object(object))
}

fn scalar_to_json(schema: &Schema, kind: &FieldType, value: &Value) -> Result<JsonValue> {
    Ok(match (kind, value) {
        (FieldType::Double, Value::Double(value)) => float_json(*value)?,
        (FieldType::Float, Value::Float(value)) => float_json(f64::from(*value))?,
        (FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32, Value::Int32(value)) => {
            JsonValue::Number(Number::from(*value))
        }
        (FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64, Value::Int64(value)) => {
            JsonValue::String(value.to_string())
        }
        (FieldType::Uint32 | FieldType::Fixed32, Value::Uint32(value)) => {
            JsonValue::Number(Number::from(*value))
        }
        (FieldType::Uint64 | FieldType::Fixed64, Value::Uint64(value)) => {
            JsonValue::String(value.to_string())
        }
        (FieldType::Bool, Value::Bool(value)) => JsonValue::Bool(*value),
        (FieldType::String, Value::String(value)) => JsonValue::String(value.clone()),
        (FieldType::String, Value::RawString(value)) => JsonValue::String(
            core::str::from_utf8(value)
                .map_err(|_| Error::new(0, "unverified string is not valid UTF-8"))?
                .to_string(),
        ),
        (FieldType::Bytes, Value::Bytes(value)) => JsonValue::String(base64_encode(value)),
        (FieldType::Enum(name), Value::Enum(_value)) if name == "google.protobuf.NullValue" => {
            JsonValue::Null
        }
        (FieldType::Enum(name), Value::Enum(value)) => {
            let enumeration = schema
                .enums
                .get(name)
                .ok_or_else(|| Error::new(0, "enum descriptor missing"))?;
            enumeration
                .values
                .iter()
                .find(|candidate| candidate.number == *value)
                .map_or_else(
                    || JsonValue::Number(Number::from(*value)),
                    |candidate| JsonValue::String(candidate.name.clone()),
                )
        }
        (FieldType::Message(name), Value::Message(value)) => message_to_json(
            schema,
            schema
                .message(name)
                .ok_or_else(|| Error::new(0, "message descriptor missing"))?,
            value,
        )?,
        _ => {
            return Err(Error::new(
                0,
                "dynamic value does not match JSON field type",
            ));
        }
    })
}

fn decode_map(
    schema: &Schema,
    key_kind: &FieldType,
    value_kind: &FieldType,
    json: &JsonValue,
    options: &JsonDecodeOptions,
) -> Result<Value> {
    let object = json
        .as_object()
        .ok_or_else(|| Error::new(0, "map JSON field must be an object"))?;
    let mut entries = Vec::with_capacity(object.len());
    for (key, value) in object {
        if value.is_null() {
            return Err(Error::new(0, "map JSON value cannot be null"));
        }
        if options.ignore_unknown_fields && unknown_enum_name(schema, value_kind, value) {
            continue;
        }
        entries.push((
            json_map_key(key_kind, key)?,
            json_to_scalar(schema, value_kind, value, options)?,
        ));
    }
    Ok(Value::Map(entries))
}

fn encode_map(
    schema: &Schema,
    key_kind: &FieldType,
    value_kind: &FieldType,
    value: &Value,
) -> Result<JsonValue> {
    let Value::Map(entries) = value else {
        return Err(Error::new(0, "map field has non-map value"));
    };
    let mut object = JsonMap::new();
    for (key, value) in entries {
        object.insert(
            map_key_string(key_kind, key)?,
            scalar_to_json(schema, value_kind, value)?,
        );
    }
    Ok(JsonValue::Object(object))
}

fn json_map_key(kind: &FieldType, value: &str) -> Result<Value> {
    match kind {
        FieldType::String => Ok(Value::String(value.to_string())),
        FieldType::Bool => match value {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(Error::new(0, "invalid boolean map key")),
        },
        FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 => value
            .parse::<i32>()
            .map(Value::Int32)
            .map_err(|_| Error::new(0, "invalid signed map key")),
        FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => value
            .parse::<i64>()
            .map(Value::Int64)
            .map_err(|_| Error::new(0, "invalid signed map key")),
        FieldType::Uint32 | FieldType::Fixed32 => value
            .parse::<u32>()
            .map(Value::Uint32)
            .map_err(|_| Error::new(0, "invalid unsigned map key")),
        FieldType::Uint64 | FieldType::Fixed64 => value
            .parse::<u64>()
            .map(Value::Uint64)
            .map_err(|_| Error::new(0, "invalid unsigned map key")),
        _ => Err(Error::new(0, "invalid protobuf map key type")),
    }
}

fn map_key_string(kind: &FieldType, value: &Value) -> Result<String> {
    match (kind, value) {
        (FieldType::String, Value::String(value)) => Ok(value.clone()),
        (FieldType::Bool, Value::Bool(value)) => Ok(value.to_string()),
        (FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32, Value::Int32(value)) => {
            Ok(value.to_string())
        }
        (FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64, Value::Int64(value)) => {
            Ok(value.to_string())
        }
        (FieldType::Uint32 | FieldType::Fixed32, Value::Uint32(value)) => Ok(value.to_string()),
        (FieldType::Uint64 | FieldType::Fixed64, Value::Uint64(value)) => Ok(value.to_string()),
        _ => Err(Error::new(0, "dynamic map key has the wrong type")),
    }
}

fn integer_i64(json: &JsonValue) -> Result<i64> {
    if let Some(value) = json.as_i64() {
        return Ok(value);
    }
    if let Some(value) = json.as_str() {
        if let Ok(integer) = value.parse() {
            return Ok(integer);
        }
        if !value.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
            return Err(Error::new(0, "invalid signed integer JSON value"));
        }
        return exact_decimal_integer(value)?
            .try_into()
            .map_err(|_| Error::new(0, "signed integer JSON value out of range"));
    }
    if let Some(number) = json.as_number() {
        return exact_decimal_integer(&number.to_string())?
            .try_into()
            .map_err(|_| Error::new(0, "signed integer JSON value out of range"));
    }
    Err(Error::new(
        0,
        "integer JSON field must be a number or decimal string",
    ))
}

fn integer_u64(json: &JsonValue) -> Result<u64> {
    if let Some(value) = json.as_u64() {
        return Ok(value);
    }
    if let Some(value) = json.as_str() {
        if let Ok(integer) = value.parse() {
            return Ok(integer);
        }
        if !value.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
            return Err(Error::new(0, "invalid unsigned integer JSON value"));
        }
        return exact_decimal_integer(value)?
            .try_into()
            .map_err(|_| Error::new(0, "unsigned integer JSON value out of range"));
    }
    if let Some(number) = json.as_number() {
        return exact_decimal_integer(&number.to_string())?
            .try_into()
            .map_err(|_| Error::new(0, "unsigned integer JSON value out of range"));
    }
    Err(Error::new(
        0,
        "integer JSON field must be a number or decimal string",
    ))
}

fn json_float(json: &JsonValue) -> Result<f64> {
    if let Some(value) = json.as_f64() {
        return Ok(value);
    }
    match json.as_str() {
        Some("NaN") => Ok(f64::NAN),
        Some("Infinity") => Ok(f64::INFINITY),
        Some("-Infinity") => Ok(f64::NEG_INFINITY),
        Some(value) => value
            .parse()
            .map_err(|_| Error::new(0, "invalid floating-point JSON value")),
        None => Err(Error::new(0, "invalid floating-point JSON value")),
    }
}

fn exact_decimal_integer(text: &str) -> Result<i128> {
    let (negative, unsigned) = if let Some(value) = text.strip_prefix('-') {
        (true, value)
    } else if let Some(value) = text.strip_prefix('+') {
        (false, value)
    } else {
        (false, text)
    };
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (
            mantissa,
            exponent
                .parse::<i32>()
                .map_err(|_| Error::new(0, "invalid integer JSON exponent"))?,
        ),
        None => (unsigned, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::new(0, "invalid integer JSON value"));
    }
    let mut value = 0i128;
    for digit in whole.bytes().chain(fraction.bytes()) {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(i128::from(digit - b'0')))
            .ok_or_else(|| Error::new(0, "integer JSON value out of range"))?;
    }
    let scale = i64::try_from(fraction.len())
        .map_err(|_| Error::new(0, "integer JSON fraction is too long"))?
        - i64::from(exponent);
    if scale.unsigned_abs() > 39 {
        if value == 0 {
            return Ok(0);
        }
        return Err(Error::new(0, "integer JSON value out of range"));
    }
    if scale > 0 {
        for _ in 0..scale {
            if value % 10 != 0 {
                return Err(Error::new(0, "integer JSON value is not integral"));
            }
            value /= 10;
        }
    } else {
        for _ in scale..0 {
            value = value
                .checked_mul(10)
                .ok_or_else(|| Error::new(0, "integer JSON value out of range"))?;
        }
    }
    if negative {
        value = value
            .checked_neg()
            .ok_or_else(|| Error::new(0, "integer JSON value out of range"))?;
    }
    Ok(value)
}

fn json_is_default(value: &Value) -> bool {
    match value {
        Value::Double(value) => *value == 0.0,
        Value::Float(value) => *value == 0.0,
        Value::Int32(value) | Value::Enum(value) => *value == 0,
        Value::Int64(value) => *value == 0,
        Value::Uint32(value) => *value == 0,
        Value::Uint64(value) => *value == 0,
        Value::Bool(value) => !value,
        Value::String(value) => value.is_empty(),
        Value::RawString(value) | Value::Bytes(value) => value.is_empty(),
        Value::Repeated(value) => value.is_empty(),
        Value::Map(value) => value.is_empty(),
        Value::Message(_) => false,
    }
}

fn float_json(value: f64) -> Result<JsonValue> {
    if value.is_nan() {
        return Ok(JsonValue::String("NaN".into()));
    }
    if value == f64::INFINITY {
        return Ok(JsonValue::String("Infinity".into()));
    }
    if value == f64::NEG_INFINITY {
        return Ok(JsonValue::String("-Infinity".into()));
    }
    Number::from_f64(value)
        .map(JsonValue::Number)
        .ok_or_else(|| Error::new(0, "floating-point value cannot be represented as JSON"))
}

fn json_enum(enumeration: &Enum, json: &JsonValue) -> Result<i32> {
    if enumeration.full_name == "google.protobuf.NullValue" && json.is_null() {
        return Ok(0);
    }
    if let Some(name) = json.as_str() {
        return enumeration
            .values
            .iter()
            .find(|candidate| candidate.name == name)
            .map(|candidate| candidate.number)
            .ok_or_else(|| Error::new(0, format!("unknown enum JSON name: {name}")));
    }
    integer_i64(json)?
        .try_into()
        .map_err(|_| Error::new(0, "enum JSON number out of range"))
}

fn unknown_enum_name(schema: &Schema, kind: &FieldType, json: &JsonValue) -> bool {
    let FieldType::Enum(name) = kind else {
        return false;
    };
    let Some(value) = json.as_str() else {
        return false;
    };
    !schema.enums.get(name).is_some_and(|enumeration| {
        enumeration
            .values
            .iter()
            .any(|candidate| candidate.name == value)
    })
}

fn decode_well_known(
    schema: &Schema,
    descriptor: &MessageDescriptor,
    json: &JsonValue,
    options: &JsonDecodeOptions,
) -> Result<Option<Message>> {
    if descriptor.full_name.starts_with("google.protobuf.")
        && descriptor.full_name.ends_with("Value")
        && descriptor.full_name != "google.protobuf.Value"
        && descriptor.full_name != "google.protobuf.ListValue"
    {
        let field = descriptor
            .field_by_number(1)
            .ok_or_else(|| Error::new(0, "wrapper value field missing"))?;
        let mut message = Message::new();
        message.insert(
            field.name.clone(),
            json_to_scalar(schema, &field.kind, json, options)?,
        );
        return Ok(Some(message));
    }
    match descriptor.full_name.as_str() {
        "google.protobuf.Any" => decode_any(schema, json, options).map(Some),
        "google.protobuf.Duration" => Ok(Some(parse_duration(json)?)),
        "google.protobuf.Timestamp" => Ok(Some(parse_timestamp(json)?)),
        "google.protobuf.Value" => {
            let (name, value) = match json {
                JsonValue::Null => ("null_value", Value::Enum(0)),
                JsonValue::Bool(value) => ("bool_value", Value::Bool(*value)),
                JsonValue::Number(_) => ("number_value", Value::Double(json_float(json)?)),
                JsonValue::String(value) => ("string_value", Value::String(value.clone())),
                JsonValue::Array(_) => {
                    let descriptor = schema
                        .message("google.protobuf.ListValue")
                        .ok_or_else(|| Error::new(0, "ListValue descriptor missing"))?;
                    (
                        "list_value",
                        Value::Message(json_to_message(schema, descriptor, json, options)?),
                    )
                }
                JsonValue::Object(_) => {
                    let descriptor = schema
                        .message("google.protobuf.Struct")
                        .ok_or_else(|| Error::new(0, "Struct descriptor missing"))?;
                    (
                        "struct_value",
                        Value::Message(json_to_message(schema, descriptor, json, options)?),
                    )
                }
            };
            let mut message = Message::new();
            message.insert(name, value);
            Ok(Some(message))
        }
        "google.protobuf.ListValue" => {
            let array = json
                .as_array()
                .ok_or_else(|| Error::new(0, "ListValue JSON must be an array"))?;
            let value_descriptor = schema
                .message("google.protobuf.Value")
                .ok_or_else(|| Error::new(0, "Value descriptor missing"))?;
            let mut values = Vec::with_capacity(array.len());
            for value in array {
                values.push(Value::Message(json_to_message(
                    schema,
                    value_descriptor,
                    value,
                    options,
                )?));
            }
            let mut message = Message::new();
            message.insert("values", Value::Repeated(values));
            Ok(Some(message))
        }
        "google.protobuf.Struct" => {
            let object = json
                .as_object()
                .ok_or_else(|| Error::new(0, "Struct JSON must be an object"))?;
            let value_descriptor = schema
                .message("google.protobuf.Value")
                .ok_or_else(|| Error::new(0, "Value descriptor missing"))?;
            let mut entries = Vec::with_capacity(object.len());
            for (key, value) in object {
                entries.push((
                    Value::String(key.clone()),
                    Value::Message(json_to_message(schema, value_descriptor, value, options)?),
                ));
            }
            let mut message = Message::new();
            message.insert("fields", Value::Map(entries));
            Ok(Some(message))
        }
        "google.protobuf.FieldMask" => {
            let source = json
                .as_str()
                .ok_or_else(|| Error::new(0, "FieldMask JSON must be a string"))?;
            if source.contains('_') {
                return Err(Error::new(
                    0,
                    "FieldMask JSON paths cannot contain underscores",
                ));
            }
            let paths = source
                .split(',')
                .filter(|path| !path.is_empty())
                .map(|path| Value::String(camel_to_snake(path)))
                .collect();
            let mut message = Message::new();
            message.insert("paths", Value::Repeated(paths));
            Ok(Some(message))
        }
        _ => Ok(None),
    }
}

fn encode_well_known(
    schema: &Schema,
    descriptor: &MessageDescriptor,
    message: &Message,
) -> Result<Option<JsonValue>> {
    if descriptor.full_name.starts_with("google.protobuf.")
        && descriptor.full_name.ends_with("Value")
        && descriptor.full_name != "google.protobuf.Value"
        && descriptor.full_name != "google.protobuf.ListValue"
    {
        let field = descriptor
            .field_by_number(1)
            .ok_or_else(|| Error::new(0, "wrapper value field missing"))?;
        let value = message
            .get(&field.name)
            .cloned()
            .unwrap_or_else(|| default_value(&field.kind));
        return scalar_to_json(schema, &field.kind, &value).map(Some);
    }
    match descriptor.full_name.as_str() {
        "google.protobuf.Any" => encode_any(schema, message).map(Some),
        "google.protobuf.Duration" => Ok(Some(JsonValue::String(format_duration(message)?))),
        "google.protobuf.Timestamp" => Ok(Some(JsonValue::String(format_timestamp(message)?))),
        "google.protobuf.Value" => {
            for field in &descriptor.fields {
                if let Some(value) = message.get(&field.name) {
                    return match field.name.as_str() {
                        "null_value" => Ok(Some(JsonValue::Null)),
                        "number_value" if matches!(value, Value::Double(number) if !number.is_finite()) => {
                            Err(Error::new(0, "Value number_value must be finite"))
                        }
                        _ => scalar_to_json(schema, &field.kind, value).map(Some),
                    };
                }
            }
            Ok(Some(JsonValue::Null))
        }
        "google.protobuf.ListValue" => {
            let values = match message.get("values") {
                Some(Value::Repeated(values)) => values,
                None => return Ok(Some(JsonValue::Array(Vec::new()))),
                _ => return Err(Error::new(0, "ListValue values have wrong type")),
            };
            let descriptor = schema
                .message("google.protobuf.Value")
                .ok_or_else(|| Error::new(0, "Value descriptor missing"))?;
            let mut array = Vec::with_capacity(values.len());
            for value in values {
                let Value::Message(value) = value else {
                    return Err(Error::new(0, "ListValue element has wrong type"));
                };
                array.push(message_to_json(schema, descriptor, value)?);
            }
            Ok(Some(JsonValue::Array(array)))
        }
        "google.protobuf.Struct" => {
            let entries = match message.get("fields") {
                Some(Value::Map(entries)) => entries,
                None => return Ok(Some(JsonValue::Object(JsonMap::new()))),
                _ => return Err(Error::new(0, "Struct fields have wrong type")),
            };
            let descriptor = schema
                .message("google.protobuf.Value")
                .ok_or_else(|| Error::new(0, "Value descriptor missing"))?;
            let mut object = JsonMap::new();
            for (key, value) in entries {
                let (Value::String(key), Value::Message(value)) = (key, value) else {
                    return Err(Error::new(0, "Struct entry has wrong type"));
                };
                object.insert(key.clone(), message_to_json(schema, descriptor, value)?);
            }
            Ok(Some(JsonValue::Object(object)))
        }
        "google.protobuf.FieldMask" => {
            let paths = match message.get("paths") {
                Some(Value::Repeated(paths)) => paths,
                None => return Ok(Some(JsonValue::String(String::new()))),
                _ => return Err(Error::new(0, "FieldMask paths have wrong type")),
            };
            let mut encoded = Vec::with_capacity(paths.len());
            for path in paths {
                let Value::String(path) = path else {
                    return Err(Error::new(0, "FieldMask path has wrong type"));
                };
                if !valid_field_mask_proto_path(path) {
                    return Err(Error::new(
                        0,
                        "FieldMask path does not round trip through JSON",
                    ));
                }
                encoded.push(snake_to_camel(path));
            }
            Ok(Some(JsonValue::String(encoded.join(","))))
        }
        _ => Ok(None),
    }
}

fn decode_any(schema: &Schema, json: &JsonValue, options: &JsonDecodeOptions) -> Result<Message> {
    let object = json
        .as_object()
        .ok_or_else(|| Error::new(0, "Any JSON must be an object"))?;
    let Some(type_url) = object.get("@type").and_then(JsonValue::as_str) else {
        if object.is_empty() {
            return Ok(Message::new());
        }
        return Err(Error::new(0, "non-empty Any JSON requires @type"));
    };
    let type_name = type_url.rsplit('/').next().unwrap_or(type_url);
    let descriptor = schema
        .message(type_name)
        .ok_or_else(|| Error::new(0, format!("unknown Any type: {type_name}")))?;
    let embedded_json = if is_custom_json_well_known(&descriptor.full_name) {
        object
            .get("value")
            .ok_or_else(|| Error::new(0, "well-known Any JSON requires value"))?
            .clone()
    } else {
        let mut embedded = object.clone();
        embedded.remove("@type");
        JsonValue::Object(embedded)
    };
    let embedded = json_to_message(schema, descriptor, &embedded_json, options)?;
    let mut message = Message::new();
    message.insert("type_url", Value::String(type_url.to_string()));
    message.insert(
        "value",
        Value::Bytes(encode(schema, descriptor, &embedded)?),
    );
    Ok(message)
}

fn encode_any(schema: &Schema, message: &Message) -> Result<JsonValue> {
    let type_url = match message.get("type_url") {
        Some(Value::String(value)) => value,
        None => return Ok(JsonValue::Object(JsonMap::new())),
        _ => return Err(Error::new(0, "Any type_url has wrong type")),
    };
    let bytes = match message.get("value") {
        Some(Value::Bytes(value)) => value.as_slice(),
        None => &[],
        _ => return Err(Error::new(0, "Any value has wrong type")),
    };
    let type_name = type_url.rsplit('/').next().unwrap_or(type_url);
    let descriptor = schema
        .message(type_name)
        .ok_or_else(|| Error::new(0, format!("unknown Any type: {type_name}")))?;
    let embedded = decode(schema, descriptor, bytes)?;
    let encoded = message_to_json(schema, descriptor, &embedded)?;
    let mut object = JsonMap::new();
    object.insert("@type".into(), JsonValue::String(type_url.clone()));
    if is_custom_json_well_known(&descriptor.full_name) {
        object.insert("value".into(), encoded);
    } else {
        let JsonValue::Object(fields) = encoded else {
            return Err(Error::new(
                0,
                "ordinary Any payload did not encode as an object",
            ));
        };
        object.extend(fields);
    }
    Ok(JsonValue::Object(object))
}

fn is_custom_json_well_known(name: &str) -> bool {
    matches!(
        name,
        "google.protobuf.Any"
            | "google.protobuf.Duration"
            | "google.protobuf.FieldMask"
            | "google.protobuf.ListValue"
            | "google.protobuf.Struct"
            | "google.protobuf.Timestamp"
            | "google.protobuf.Value"
            | "google.protobuf.BoolValue"
            | "google.protobuf.BytesValue"
            | "google.protobuf.DoubleValue"
            | "google.protobuf.FloatValue"
            | "google.protobuf.Int32Value"
            | "google.protobuf.Int64Value"
            | "google.protobuf.StringValue"
            | "google.protobuf.UInt32Value"
            | "google.protobuf.UInt64Value"
    )
}

const DURATION_MAX_SECONDS: i64 = 315_576_000_000;
const TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800;
const TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799;
const NANOS_PER_SECOND: i32 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

fn parse_duration(json: &JsonValue) -> Result<Message> {
    let text = json
        .as_str()
        .ok_or_else(|| Error::new(0, "Duration JSON must be a string"))?;
    let number = text
        .strip_suffix('s')
        .ok_or_else(|| Error::new(0, "Duration JSON must end in s"))?;
    let negative = number.starts_with('-');
    let unsigned = number.strip_prefix('-').unwrap_or(number);
    let (seconds_text, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if seconds_text.is_empty()
        || fraction.len() > 9
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::new(0, "invalid Duration JSON"));
    }
    let mut seconds: i64 = seconds_text
        .parse()
        .map_err(|_| Error::new(0, "invalid Duration seconds"))?;
    let mut nanos = if fraction.is_empty() {
        0
    } else {
        let value: i32 = fraction
            .parse()
            .map_err(|_| Error::new(0, "invalid Duration fraction"))?;
        value * 10_i32.pow((9 - fraction.len()) as u32)
    };
    if negative {
        seconds = -seconds;
        nanos = -nanos;
    }
    validate_duration(seconds, nanos)?;
    let mut message = Message::new();
    if seconds != 0 {
        message.insert("seconds", Value::Int64(seconds));
    }
    if nanos != 0 {
        message.insert("nanos", Value::Int32(nanos));
    }
    Ok(message)
}

fn format_duration(message: &Message) -> Result<String> {
    let seconds = message_i64(message, "seconds")?;
    let nanos = message_i32(message, "nanos")?;
    validate_duration(seconds, nanos)?;
    let negative = seconds < 0 || nanos < 0;
    let mut output = if negative {
        format!("-{}", seconds.unsigned_abs())
    } else {
        seconds.to_string()
    };
    append_fraction(&mut output, nanos.unsigned_abs());
    output.push('s');
    Ok(output)
}

fn validate_duration(seconds: i64, nanos: i32) -> Result<()> {
    if !(-DURATION_MAX_SECONDS..=DURATION_MAX_SECONDS).contains(&seconds)
        || !(-999_999_999..=999_999_999).contains(&nanos)
        || (seconds > 0 && nanos < 0)
        || (seconds < 0 && nanos > 0)
    {
        return Err(Error::new(0, "Duration is outside its valid range"));
    }
    Ok(())
}

fn parse_timestamp(json: &JsonValue) -> Result<Message> {
    let text = json
        .as_str()
        .ok_or_else(|| Error::new(0, "Timestamp JSON must be a string"))?;
    if text.len() < 20
        || text.as_bytes().get(4) != Some(&b'-')
        || text.as_bytes().get(10) != Some(&b'T')
    {
        return Err(Error::new(0, "invalid Timestamp JSON"));
    }
    let year = parse_slice::<i32>(text, 0, 4)?;
    let month = parse_slice::<u32>(text, 5, 7)?;
    let day = parse_slice::<u32>(text, 8, 10)?;
    let hour = parse_slice::<i64>(text, 11, 13)?;
    let minute = parse_slice::<i64>(text, 14, 16)?;
    let second = parse_slice::<i64>(text, 17, 19)?;
    if text.as_bytes().get(7) != Some(&b'-')
        || text.as_bytes().get(13) != Some(&b':')
        || text.as_bytes().get(16) != Some(&b':')
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(Error::new(0, "invalid Timestamp date or time"));
    }
    let mut cursor = 19;
    let mut nanos = 0i32;
    if text.as_bytes().get(cursor) == Some(&b'.') {
        cursor += 1;
        let start = cursor;
        while text.as_bytes().get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        let fraction = &text[start..cursor];
        if fraction.is_empty() || fraction.len() > 9 {
            return Err(Error::new(0, "invalid Timestamp fraction"));
        }
        nanos = fraction
            .parse::<i32>()
            .map_err(|_| Error::new(0, "invalid Timestamp fraction"))?
            * 10_i32.pow((9 - fraction.len()) as u32);
    }
    let offset = match text.get(cursor..) {
        Some("Z") => 0,
        Some(zone) if zone.len() == 6 && matches!(zone.as_bytes()[0], b'+' | b'-') => {
            let hours: i64 = zone[1..3]
                .parse()
                .map_err(|_| Error::new(0, "invalid Timestamp offset"))?;
            let minutes: i64 = zone[4..6]
                .parse()
                .map_err(|_| Error::new(0, "invalid Timestamp offset"))?;
            if zone.as_bytes()[3] != b':' || hours > 23 || minutes > 59 {
                return Err(Error::new(0, "invalid Timestamp offset"));
            }
            let offset = hours * 3600 + minutes * 60;
            if zone.as_bytes()[0] == b'-' {
                -offset
            } else {
                offset
            }
        }
        _ => return Err(Error::new(0, "Timestamp requires Z or a numeric offset")),
    };
    let seconds =
        days_from_civil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second
            - offset;
    validate_timestamp(seconds, nanos)?;
    let mut message = Message::new();
    if seconds != 0 {
        message.insert("seconds", Value::Int64(seconds));
    }
    if nanos != 0 {
        message.insert("nanos", Value::Int32(nanos));
    }
    Ok(message)
}

fn format_timestamp(message: &Message) -> Result<String> {
    let seconds = message_i64(message, "seconds")?;
    let nanos = message_i32(message, "nanos")?;
    validate_timestamp(seconds, nanos)?;
    let days = seconds.div_euclid(SECONDS_PER_DAY);
    let daytime = seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let hour = daytime / 3600;
    let minute = daytime % 3600 / 60;
    let second = daytime % 60;
    let mut output = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    append_fraction(&mut output, nanos as u32);
    output.push('Z');
    Ok(output)
}

fn validate_timestamp(seconds: i64, nanos: i32) -> Result<()> {
    if !(TIMESTAMP_MIN_SECONDS..=TIMESTAMP_MAX_SECONDS).contains(&seconds)
        || !(0..NANOS_PER_SECOND).contains(&nanos)
    {
        return Err(Error::new(0, "Timestamp is outside its valid range"));
    }
    Ok(())
}

fn append_fraction(output: &mut String, nanos: u32) {
    if nanos == 0 {
        return;
    }
    let digits = if nanos.is_multiple_of(1_000_000) {
        3
    } else if nanos.is_multiple_of(1_000) {
        6
    } else {
        9
    };
    output.push('.');
    let fraction = format!("{nanos:09}");
    output.push_str(&fraction[..digits]);
}

fn message_i64(message: &Message, name: &str) -> Result<i64> {
    match message.get(name) {
        Some(Value::Int64(value)) => Ok(*value),
        None => Ok(0),
        _ => Err(Error::new(0, "well-known seconds field has wrong type")),
    }
}

fn message_i32(message: &Message, name: &str) -> Result<i32> {
    match message.get(name) {
        Some(Value::Int32(value)) => Ok(*value),
        None => Ok(0),
        _ => Err(Error::new(0, "well-known nanos field has wrong type")),
    }
}

fn parse_slice<T: core::str::FromStr>(text: &str, start: usize, end: usize) -> Result<T> {
    text.get(start..end)
        .ok_or_else(|| Error::new(0, "truncated Timestamp"))?
        .parse()
        .map_err(|_| Error::new(0, "invalid Timestamp number"))
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i32::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era * 146_097 + day_of_era - 719_468)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year as i32, month as u32, day as u32)
}

fn default_value(kind: &FieldType) -> Value {
    match kind {
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
        FieldType::Map(..) => Value::Map(Vec::new()),
    }
}

fn camel_to_snake(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            output.push('_');
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn snake_to_camel(value: &str) -> String {
    let mut output = String::new();
    let mut uppercase = false;
    for character in value.chars() {
        if character == '_' {
            uppercase = true;
        } else if uppercase {
            output.push(character.to_ascii_uppercase());
            uppercase = false;
        } else {
            output.push(character);
        }
    }
    output
}

fn valid_field_mask_proto_path(value: &str) -> bool {
    let mut after_underscore = false;
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            return false;
        }
        if character == '_' {
            if after_underscore {
                return false;
            }
            after_underscore = true;
        } else {
            if after_underscore && !character.is_ascii_lowercase() {
                return false;
            }
            after_underscore = false;
        }
    }
    !after_underscore
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(BASE64[((value >> 18) & 63) as usize] as char);
        output.push(BASE64[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            BASE64[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            BASE64[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn base64_decode(input: &str, max_decoded_bytes: usize) -> Result<Vec<u8>> {
    let padding = input.bytes().rev().take_while(|byte| *byte == b'=').count();
    if padding > 2 || input[..input.len().saturating_sub(padding)].contains('=') {
        return Err(Error::new(0, "invalid base64 padding"));
    }
    let data_len = input.len().saturating_sub(padding);
    if padding != 0 && !input.len().is_multiple_of(4) {
        return Err(Error::new(0, "invalid padded base64 length"));
    }
    let mut sextets = Vec::new();
    for byte in input.bytes().take(data_len) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return Err(Error::new(0, "invalid base64 character")),
        };
        sextets.push(value);
    }
    if sextets.len() % 4 == 1 {
        return Err(Error::new(0, "invalid base64 length"));
    }
    if (padding == 1 && sextets.len() % 4 != 3) || (padding == 2 && sextets.len() % 4 != 2) {
        return Err(Error::new(0, "invalid base64 padding length"));
    }
    let tail = match sextets.len() % 4 {
        2 => 1,
        3 => 2,
        _ => 0,
    };
    let decoded_len = sextets
        .len()
        .checked_div(4)
        .and_then(|length| length.checked_mul(3))
        .and_then(|length| length.checked_add(tail))
        .ok_or_else(|| Error::new(0, "decoded base64 size overflow"))?;
    if decoded_len > max_decoded_bytes {
        return Err(Error::new(0, "decoded bytes exceed configured size limit"));
    }
    let mut output = Vec::with_capacity(decoded_len);
    for chunk in sextets.chunks(4) {
        let value = (u32::from(chunk[0]) << 18)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 12)
            | (u32::from(*chunk.get(2).unwrap_or(&0)) << 6)
            | u32::from(*chunk.get(3).unwrap_or(&0));
        output.push((value >> 16) as u8);
        if chunk.len() > 2 {
            output.push((value >> 8) as u8);
        }
        if chunk.len() > 3 {
            output.push(value as u8);
        }
    }
    Ok(output)
}

fn reject_duplicate_json_keys(input: &str, options: &JsonDecodeOptions) -> Result<()> {
    let mut cursor = 0;
    scan_json_value(input.as_bytes(), &mut cursor, options, 0)?;
    Ok(())
}

fn scan_json_value(
    bytes: &[u8],
    cursor: &mut usize,
    options: &JsonDecodeOptions,
    depth: usize,
) -> Result<()> {
    if depth > options.max_nesting_depth {
        return Err(Error::new(*cursor, "JSON exceeds configured nesting limit"));
    }
    skip_json_space(bytes, cursor);
    match bytes.get(*cursor) {
        Some(b'{') => scan_json_object(bytes, cursor, options, depth),
        Some(b'[') => scan_json_array(bytes, cursor, options, depth),
        Some(b'"') => scan_json_string(bytes, cursor, options),
        Some(_) => {
            while bytes
                .get(*cursor)
                .is_some_and(|byte| !matches!(byte, b',' | b']' | b'}'))
            {
                *cursor += 1;
            }
            Ok(())
        }
        None => Err(Error::new(*cursor, "truncated JSON value")),
    }
}

fn scan_json_object(
    bytes: &[u8],
    cursor: &mut usize,
    options: &JsonDecodeOptions,
    depth: usize,
) -> Result<()> {
    *cursor += 1;
    let mut names = BTreeSet::new();
    loop {
        skip_json_space(bytes, cursor);
        if bytes.get(*cursor) == Some(&b'}') {
            *cursor += 1;
            return Ok(());
        }
        let start = *cursor;
        if names.len() >= options.max_object_fields {
            return Err(Error::new(
                start,
                "JSON object exceeds configured field limit",
            ));
        }
        scan_json_string(bytes, cursor, options)?;
        let key: String = serde_json::from_slice(
            bytes
                .get(start..*cursor)
                .ok_or_else(|| Error::new(start, "invalid JSON key bounds"))?,
        )
        .map_err(|_| Error::new(start, "invalid JSON object key"))?;
        if !names.insert(key.clone()) {
            return Err(Error::new(start, format!("duplicate JSON field: {key}")));
        }
        skip_json_space(bytes, cursor);
        if bytes.get(*cursor) != Some(&b':') {
            return Err(Error::new(*cursor, "JSON object key requires colon"));
        }
        *cursor += 1;
        scan_json_value(bytes, cursor, options, depth + 1)?;
        skip_json_space(bytes, cursor);
        match bytes.get(*cursor) {
            Some(b',') => *cursor += 1,
            Some(b'}') => {
                *cursor += 1;
                return Ok(());
            }
            _ => return Err(Error::new(*cursor, "invalid JSON object separator")),
        }
    }
}

fn scan_json_array(
    bytes: &[u8],
    cursor: &mut usize,
    options: &JsonDecodeOptions,
    depth: usize,
) -> Result<()> {
    *cursor += 1;
    let mut values = 0usize;
    loop {
        skip_json_space(bytes, cursor);
        if bytes.get(*cursor) == Some(&b']') {
            *cursor += 1;
            return Ok(());
        }
        if values >= options.max_array_values {
            return Err(Error::new(
                *cursor,
                "JSON array exceeds configured value limit",
            ));
        }
        values += 1;
        scan_json_value(bytes, cursor, options, depth + 1)?;
        skip_json_space(bytes, cursor);
        match bytes.get(*cursor) {
            Some(b',') => *cursor += 1,
            Some(b']') => {
                *cursor += 1;
                return Ok(());
            }
            _ => return Err(Error::new(*cursor, "invalid JSON array separator")),
        }
    }
}

fn scan_json_string(bytes: &[u8], cursor: &mut usize, options: &JsonDecodeOptions) -> Result<()> {
    if bytes.get(*cursor) != Some(&b'"') {
        return Err(Error::new(*cursor, "JSON object key must be a string"));
    }
    *cursor += 1;
    let start = *cursor;
    let mut escaped = false;
    while let Some(byte) = bytes.get(*cursor) {
        *cursor += 1;
        if cursor.saturating_sub(start) > options.max_string_bytes {
            return Err(Error::new(
                start,
                "JSON string exceeds configured size limit",
            ));
        }
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            return Ok(());
        }
    }
    Err(Error::new(*cursor, "unterminated JSON string"))
}

fn skip_json_space(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        *cursor += 1;
    }
}
