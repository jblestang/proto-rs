//! Named constants from the Protocol Buffers binary and schema specifications.

/// Hexadecimal digits required after a protobuf `\u` escape.
pub(crate) const SHORT_UNICODE_ESCAPE_DIGITS: usize = 4;
/// Hexadecimal digits required after a protobuf `\U` escape.
pub(crate) const LONG_UNICODE_ESCAPE_DIGITS: usize = 8;

/// `syntax` declaration keyword.
pub(crate) const KW_SYNTAX: &str = "syntax";
/// `package` declaration keyword.
pub(crate) const KW_PACKAGE: &str = "package";
/// `import` declaration keyword.
pub(crate) const KW_IMPORT: &str = "import";
/// `public` import modifier.
pub(crate) const KW_PUBLIC: &str = "public";
/// `weak` import modifier.
pub(crate) const KW_WEAK: &str = "weak";
/// `message` declaration keyword.
pub(crate) const KW_MESSAGE: &str = "message";
/// `enum` declaration keyword.
pub(crate) const KW_ENUM: &str = "enum";
/// `oneof` declaration keyword.
pub(crate) const KW_ONEOF: &str = "oneof";
/// `option` declaration keyword.
pub(crate) const KW_OPTION: &str = "option";
/// `reserved` declaration keyword.
pub(crate) const KW_RESERVED: &str = "reserved";
/// `extensions` declaration keyword.
pub(crate) const KW_EXTENSIONS: &str = "extensions";
/// `extend` declaration keyword.
pub(crate) const KW_EXTEND: &str = "extend";
/// `required` field cardinality keyword.
pub(crate) const KW_REQUIRED: &str = "required";
/// `optional` field cardinality keyword.
pub(crate) const KW_OPTIONAL: &str = "optional";
/// `repeated` field cardinality keyword.
pub(crate) const KW_REPEATED: &str = "repeated";
/// Legacy proto2 `group` field keyword.
pub(crate) const KW_GROUP: &str = "group";
/// `map` field-type keyword.
pub(crate) const KW_MAP: &str = "map";
/// `service` declaration keyword.
pub(crate) const KW_SERVICE: &str = "service";
/// Range keyword separating inclusive reserved endpoints.
pub(crate) const KW_TO: &str = "to";
/// Keyword selecting the largest legal reserved range endpoint.
pub(crate) const KW_MAX: &str = "max";
/// Field option controlling packed repeated encoding.
pub(crate) const OPTION_PACKED: &str = "packed";
/// Proto2 field option declaring an accessor default.
pub(crate) const OPTION_DEFAULT: &str = "default";
/// Enum option permitting multiple names to share a numeric value.
pub(crate) const OPTION_ALLOW_ALIAS: &str = "allow_alias";
/// Boolean option spelling representing an enabled option.
pub(crate) const BOOLEAN_TRUE: &str = "true";
/// Boolean option spelling representing a disabled option.
pub(crate) const BOOLEAN_FALSE: &str = "false";
/// Source spelling selecting proto2 parsing rules.
pub(crate) const SYNTAX_PROTO2: &str = "proto2";
/// Source spelling selecting proto3 parsing rules.
pub(crate) const SYNTAX_PROTO3: &str = "proto3";

/// Source spelling of the protobuf `double` scalar type.
pub(crate) const TYPE_DOUBLE: &str = "double";
/// Source spelling of the protobuf `float` scalar type.
pub(crate) const TYPE_FLOAT: &str = "float";
/// Source spelling of the protobuf `int32` scalar type.
pub(crate) const TYPE_INT32: &str = "int32";
/// Source spelling of the protobuf `int64` scalar type.
pub(crate) const TYPE_INT64: &str = "int64";
/// Source spelling of the protobuf `uint32` scalar type.
pub(crate) const TYPE_UINT32: &str = "uint32";
/// Source spelling of the protobuf `uint64` scalar type.
pub(crate) const TYPE_UINT64: &str = "uint64";
/// Source spelling of the protobuf `sint32` scalar type.
pub(crate) const TYPE_SINT32: &str = "sint32";
/// Source spelling of the protobuf `sint64` scalar type.
pub(crate) const TYPE_SINT64: &str = "sint64";
/// Source spelling of the protobuf `fixed32` scalar type.
pub(crate) const TYPE_FIXED32: &str = "fixed32";
/// Source spelling of the protobuf `fixed64` scalar type.
pub(crate) const TYPE_FIXED64: &str = "fixed64";
/// Source spelling of the protobuf `sfixed32` scalar type.
pub(crate) const TYPE_SFIXED32: &str = "sfixed32";
/// Source spelling of the protobuf `sfixed64` scalar type.
pub(crate) const TYPE_SFIXED64: &str = "sfixed64";
/// Source spelling of the protobuf `bool` scalar type.
pub(crate) const TYPE_BOOL: &str = "bool";
/// Source spelling of the protobuf `string` scalar type.
pub(crate) const TYPE_STRING: &str = "string";
/// Source spelling of the protobuf `bytes` scalar type.
pub(crate) const TYPE_BYTES: &str = "bytes";

/// Smallest field number permitted by the protobuf language.
pub(crate) const MIN_FIELD_NUMBER: u32 = 1;
/// Largest field number representable by protobuf's 29-bit field-number space.
pub(crate) const MAX_FIELD_NUMBER: u32 = 536_870_911;
/// First field number reserved for protobuf implementations.
pub(crate) const RESERVED_FIELD_NUMBER_START: u32 = 19_000;
/// Last field number reserved for protobuf implementations.
pub(crate) const RESERVED_FIELD_NUMBER_END: u32 = 19_999;

/// Number of low key bits occupied by the wire type.
pub(crate) const FIELD_NUMBER_SHIFT: usize = 3;
/// Mask selecting the three-bit wire type from an encoded field key.
pub(crate) const WIRE_TYPE_MASK: u64 = 0x07;
/// Varint wire type used by integers, booleans, and enums.
pub(crate) const WIRE_TYPE_VARINT: u8 = 0;
/// 64-bit wire type used by fixed64, sfixed64, and double.
pub(crate) const WIRE_TYPE_FIXED64: u8 = 1;
/// Length-delimited wire type used by strings, bytes, messages, and packing.
pub(crate) const WIRE_TYPE_LENGTH_DELIMITED: u8 = 2;
/// 32-bit wire type used by fixed32, sfixed32, and float.
pub(crate) const WIRE_TYPE_FIXED32: u8 = 5;

/// Number of payload bits stored in each varint byte.
pub(crate) const VARINT_BITS_PER_BYTE: usize = 7;
/// Mask selecting the seven payload bits of a varint byte.
pub(crate) const VARINT_DATA_MASK: u8 = 0x7f;
/// Continuation bit indicating that another varint byte follows.
pub(crate) const VARINT_CONTINUATION_BIT: u8 = 0x80;
/// Maximum bytes required to represent an unsigned 64-bit varint.
pub(crate) const MAX_VARINT_BYTES: usize = 10;
/// Maximum bytes permitted for a 32-bit protobuf field key.
pub(crate) const MAX_FIELD_KEY_BYTES: usize = 5;
/// Largest valid final byte in a ten-byte unsigned 64-bit varint.
pub(crate) const MAX_TENTH_VARINT_BYTE: u8 = 1;
/// Default maximum nested-message depth used by compatibility decoding.
pub(crate) const DEFAULT_RECURSION_LIMIT: usize = 100;
/// Canonical quiet-NaN bit pattern used for normalized 32-bit floats.
pub(crate) const CANONICAL_F32_NAN_BITS: u32 = 0x7fc0_0000;
/// Canonical quiet-NaN bit pattern used for normalized 64-bit floats.
pub(crate) const CANONICAL_F64_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

/// Size in bytes of a fixed-width 32-bit wire value.
pub(crate) const FIXED32_SIZE: usize = 4;
/// Size in bytes of a fixed-width 64-bit wire value.
pub(crate) const FIXED64_SIZE: usize = 8;
/// Shift exposing the sign bit of a signed 32-bit value for zig-zag encoding.
pub(crate) const I32_SIGN_SHIFT: usize = 31;
/// Shift exposing the sign bit of a signed 64-bit value for zig-zag encoding.
pub(crate) const I64_SIGN_SHIFT: usize = 63;
/// Synthetic map-entry field number containing the key.
pub(crate) const MAP_KEY_FIELD_NUMBER: u32 = 1;
/// Synthetic map-entry field number containing the value.
pub(crate) const MAP_VALUE_FIELD_NUMBER: u32 = 2;

/// Builds a protobuf wire key from a validated field number and wire type.
pub(crate) const fn make_key(field_number: u32, wire_type: u8) -> u64 {
    ((field_number as u64) << FIELD_NUMBER_SHIFT) | wire_type as u64
}

/// Returns whether the codec implements the supplied protobuf wire type.
pub(crate) const fn is_supported_wire_type(wire_type: u8) -> bool {
    matches!(
        wire_type,
        WIRE_TYPE_VARINT | WIRE_TYPE_FIXED64 | WIRE_TYPE_LENGTH_DELIMITED | WIRE_TYPE_FIXED32
    )
}
