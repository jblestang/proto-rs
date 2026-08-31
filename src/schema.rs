//! Protocol Buffers source parser and descriptor registry.
//!
//! # Registry-first loading
//!
//! [`Registry`] is the only cross-file source-loading abstraction.
//! It owns source strings under protobuf import paths.
//! Callers populate it completely before requesting a parse.
//! The registry does not open files or contact external services.
//! Applications may load its contents from any environment-specific source.
//! Embedded applications can register static strings copied into allocation.
//! Hosted applications can read files before invoking the parser.
//! Tests can construct complete virtual source trees in memory.
//! Re-registering a path replaces the previous source and returns it.
//! Parsing starts from one registered root path.
//! Only sources reachable through imports are parsed and merged.
//! Normal imports must resolve to a registered source.
//! Public imports must also resolve to a registered source.
//! Missing weak imports are tolerated.
//! Direct imports expose their declarations to the importing source.
//! Only public imports re-export declarations to the next import level.
//! Cyclic imports are rejected after the reachable graph is collected.
//! Duplicate symbols across loaded sources are rejected.
//! Registry parsing preserves the root file's package and syntax metadata.
//!
//! # Single-source parsing
//!
//! [`parse`] remains convenient for schemas without imports.
//! It parses one source and resolves all locally declared user types.
//! An unresolved imported type therefore produces a useful error.
//! Cross-file users should prefer [`Registry::parse`].
//! Neither entry point has hidden global state.
//! Neither entry point caches descriptors between calls.
//! Returned [`Schema`] values own their descriptors and names.
//!
//! # Pest grammar and lexical model
//!
//! The checked-in `proto.pest` grammar recognizes protobuf syntax.
//! Pest generates the grammar parser while compiling this crate; parsing a
//! user-provided `.proto` source never generates Rust code or message types.
//! The same grammar produces the token stream consumed by descriptor building.
//! It recognizes protobuf identifiers and qualified identifiers.
//! A leading dot is retained for absolute type-name resolution.
//! Decimal, octal, hexadecimal, exponent, signed, and large numeric literals
//! are retained as text until a grammar position requires an integer.
//! This permits proto2 default literals larger than a signed 64-bit value.
//! Field numbers and enum numbers are parsed into bounded integers.
//! Both single-quoted and double-quoted strings are recognized.
//! Line comments beginning with `//` are ignored.
//! Block comments delimited by `/*` and `*/` are ignored.
//! Unterminated strings and block comments produce offset-bearing errors.
//! Punctuation is represented as individual symbol tokens.
//! Whitespace has no semantic meaning outside quoted strings.
//! The lexer allocates owned token text to simplify later descriptor ownership.
//!
//! # File grammar
//!
//! Proto2 and proto3 syntax declarations are recognized.
//! A missing syntax declaration follows the historical proto2 default.
//! Package declarations qualify top-level messages and enums.
//! Normal, public, and weak import declarations are retained.
//! File options are retained and checked against their descriptor scope.
//! Services and RPC methods are retained with resolved message endpoints.
//! Unknown or malformed top-level statements are rejected by the grammar.
//! Valid non-wire declarations are checked syntactically but not retained.
//!
//! # Message grammar
//!
//! Top-level and nested messages are represented by [`MessageDescriptor`].
//! Nested names include every enclosing message component.
//! Message fields retain source declaration order.
//! Nested enums are stored alongside top-level enums by full name.
//! Oneof declarations attach a shared group name to member fields.
//! Reserved names and ranges are parsed and checked against declared fields.
//! Extension ranges are recognized and skipped in the basic proto2 tier.
//! Extend blocks are recognized and skipped in the basic proto2 tier.
//! Legacy group declarations are recognized and structurally skipped.
//! Skipping groups lets surrounding basic proto2 fields remain usable.
//! Declared group descriptors and MessageSet semantics remain exclusions.
//! Unknown group wire values are safely skipped, audited, and preservable.
//!
//! # Field descriptors
//!
//! [`Field`] records name, number, cardinality, type, packing, and presence.
//! It also retains a raw proto2 default literal when one is declared.
//! Field numbers must be positive.
//! Field numbers may not exceed 536,870,911.
//! The implementation-reserved range 19,000 through 19,999 is rejected.
//! Proto2 `required`, `optional`, and `repeated` labels are retained.
//! Proto3 unlabeled scalar fields use optional cardinality without presence.
//! Proto3 explicit `optional` fields have explicit presence.
//! Oneof members always have explicit presence.
//! Resolved message fields always have explicit presence.
//! Map declarations always have repeated cardinality internally.
//!
//! # Scalar types
//!
//! Every protobuf scalar wire type has a [`FieldType`] variant.
//! `double` and `float` retain their IEEE width.
//! `int32` and `int64` retain two's-complement varint semantics.
//! `uint32` and `uint64` retain unsigned varint semantics.
//! `sint32` and `sint64` identify zig-zag transformation.
//! Fixed and signed-fixed variants retain their exact width.
//! Boolean fields use the varint wire family.
//! String fields require UTF-8 at codec decode time.
//! Bytes fields remain opaque.
//! Message and enum variants retain fully resolved names.
//! Map variants own resolved key and value types.
//!
//! # Type resolution
//!
//! User-defined field types are initially retained as source names.
//! Resolution occurs only after every reachable file has been parsed.
//! Absolute names beginning with a dot are looked up from the schema root.
//! Relative names are searched from the innermost message scope outward.
//! Package scope is naturally visited while walking outward.
//! An unqualified global candidate is checked last.
//! Message names resolve to [`FieldType::Message`].
//! Enum names resolve to [`FieldType::Enum`].
//! Unknown names cause parsing to fail instead of becoming opaque placeholders.
//! Cross-file names use the same resolution rules as local names.
//! This phase also finalizes explicit presence and packing metadata.
//!
//! # Semantic pass ordering
//!
//! Parsing and semantic resolution are deliberately separate operations.
//! Pest first proves that every token belongs to the protobuf grammar.
//! The descriptor builder then checks declarations local to one source file.
//! Registry traversal collects every source reachable from the selected root.
//! Required imports must exist before any type lookup is attempted.
//! Weak imports may be absent and then contribute no declarations.
//! A depth-first graph pass rejects self-imports and longer import cycles.
//! Visibility is computed independently for every reachable source file.
//! Direct imports expose all declarations to the importing file.
//! A public import additionally exposes its declarations to later importers.
//! Ordinary transitive imports do not accidentally leak private declarations.
//! Declaration resolution runs for every file before option uses are checked.
//! This ordering lets consumers use options declared in imported source files.
//! It also lets an option declaration privately import its own value message.
//! Field and RPC types use the visibility of the file that mentions the name.
//! Custom extension value types use the visibility of their declaring file.
//! Option uses use the fully resolved extension descriptor from that first pass.
//! The final merge occurs only after every file passes its local semantic checks.
//! Merge conflicts therefore cannot leave a partially valid public [`Schema`].
//! All maps used during these passes are deterministic allocation-backed trees.
//!
//! # Proto3 declaration invariants
//!
//! Proto3 fields cannot use the legacy `required` cardinality.
//! An explicit `optional` field is distinguished from an implicit singular field.
//! Message fields retain presence regardless of whether `optional` was written.
//! Oneof members retain presence and may not carry cardinality labels.
//! Map fields cannot be labeled, packed, nested inside oneof, or used as keys.
//! Every map key must belong to the scalar key subset defined by protobuf.
//! Field numbers are checked against both the numeric limit and reserved range.
//! A field cannot reuse a reserved name or any number in a reserved interval.
//! Field names, nested declarations, oneofs, and enum values share their proper
//! protobuf namespaces and are rejected when those namespaces collide.
//! Derived and explicit JSON field names must also be unique within a message.
//! This JSON-name rule is semantic even though this crate has no JSON codec.
//! Proto3 enum declarations must start with a member whose numeric value is zero.
//! Duplicate enum names are always invalid.
//! Duplicate enum numbers require an explicit `allow_alias = true` option.
//! Enum values cannot reuse names or numbers reserved by their declaration.
//! A proto3 field cannot refer to an enum declared by a proto2 source file.
//! It may refer to a proto2 message because message wire semantics are compatible.
//! Groups and ordinary extension ranges remain illegal proto3 declarations.
//! The only accepted proto3 `extend` target is a descriptor options message.
//! Custom-option field numbers must belong to the descriptor extension range.
//! Unknown declarations fail instead of being silently discarded as fields.
//!
//! # Option resolution guarantees
//!
//! Every option occurrence retains its normalized source name and value text.
//! Its lexical kind distinguishes identifiers, strings, numbers, and aggregates.
//! Built-in names are checked against the descriptor scope where they appear.
//! Thus a valid field option cannot be misplaced on a file or service.
//! Boolean built-ins accept only the protobuf identifiers `true` and `false`.
//! String built-ins require a quoted string literal.
//! Enum-shaped built-ins require an identifier and validate their known members.
//! Singular built-in options may not occur more than once at the same scope.
//! A custom option name begins with a parenthesized extension reference.
//! Absolute custom names bypass lexical lookup just like absolute type names.
//! Relative custom names search the innermost scope and then each parent scope.
//! The resolved extension must target the options message for the current scope.
//! For example, a `FieldOptions` extension cannot be attached to a message.
//! Singular custom options reject repeated assignments of the same option path.
//! Repeated custom extension fields permit repeated assignments in source order.
//! Scalar custom options require the matching literal category.
//! Enum custom options accept either a symbolic identifier or numeric literal.
//! Message-valued custom options require a braced aggregate at their root.
//! A dotted custom-option suffix traverses resolved message fields one component
//! at a time and rejects unknown components or traversal through scalar values.
//! Custom map option values are rejected because extensions cannot be map fields.
//! Descriptor option messages themselves must be visible through the Registry.
//! This prevents a well-known type spelling from substituting for a real import.
//!
//! # Service descriptor guarantees
//!
//! Services participate in the same package namespace as messages and enums.
//! Each service retains its source order, options, and package-qualified name.
//! Method names must be unique within their containing service.
//! Request and response names use ordinary protobuf lexical lookup.
//! Both endpoints must resolve to message declarations rather than enums.
//! Client-streaming and server-streaming modifiers are retained independently.
//! Method option blocks and semicolon-only methods produce the same descriptor
//! shape except for their retained option collections.
//! Services do not affect binary message encoding but remain reflection data.
//! Invalid services prevent the complete schema from being returned.
//!
//! # Wire groups versus group declarations
//!
//! Proto3 never permits a declared group field in its source schema.
//! Binary protobuf still reserves start-group and end-group wire tags.
//! A newer or legacy sender can therefore place an unknown group on the wire.
//! The codec treats that occurrence as unknown structured data, not a declaration.
//! It recursively verifies nesting and matching end-group field numbers.
//! Exact bytes can be retained for compatibility forwarding and auditing.
//! This does not synthesize a typed group descriptor or expose group members.
//! MessageSet-shaped unknown data benefits from the same preservation behavior.
//! Passing those wire round trips does not imply typed MessageSet reflection.
//!
//! # Enums
//!
//! [`Enum`] retains its short name, full name, and ordered values.
//! [`EnumValue`] retains both symbolic name and signed numeric value.
//! Negative enum values are supported.
//! Aliases are retained as independent ordered declarations.
//! Enum options are retained, validated, and `allow_alias` is interpreted.
//! Unknown enum numbers remain valid at wire decode time.
//! Proto3 enums must declare a zero-valued first member.
//! Duplicate numeric values require `option allow_alias = true`.
//!
//! # Maps
//!
//! Map syntax is represented directly instead of exposing synthetic messages.
//! Valid key types are signed and unsigned integer families, bool, and string.
//! Floating-point, bytes, enum, message, and map keys are rejected.
//! Map values may use any non-map protobuf field type.
//! User-defined map value names resolve after the import graph is loaded.
//! Map fields are never packed.
//! The codec translates map descriptors to synthetic entry wire messages.
//!
//! # Packing
//!
//! Explicit `[packed = true]` and `[packed = false]` values are retained.
//! Proto3 packable repeated fields default to packed.
//! Proto2 packable repeated fields default to unpacked.
//! An unresolved user type provisionally inherits the file syntax default.
//! Resolution disables packing if that type is a message.
//! Resolution retains the packing default if that type is an enum.
//! Strings, bytes, maps, and messages are always marked unpacked.
//! Decoding still accepts either representation for packable primitives.
//!
//! # Proto2 defaults
//!
//! Default option values are stored as raw normalized token text.
//! Signed integer literals retain their sign.
//! Large unsigned literals do not overflow the lexer.
//! Floating exponent literals remain available to reflection callers.
//! String and bytes defaults retain their decoded quoted contents.
//! Boolean and enum symbolic defaults retain their identifier text.
//! The dynamic message map represents wire presence, not accessor defaults.
//! Callers can inspect [`Field::default`] when an absent-value view is needed.
//! Encoding never writes an absent field merely because it declares a default.
//! Required fields remain required independently of their default literal.
//!
//! # Options and non-wire declarations
//!
//! Built-in options are retained and validated for descriptor scope and type.
//! The parser interprets field `packed` and `default` where they affect wire
//! behavior and enum `allow_alias` where it affects declaration validity.
//! Proto3 custom-option extensions of descriptor option messages are retained.
//! Custom-option uses undergo lexical lookup, scope, duplicate, path, and value
//! validation against the resolved extension field descriptor.
//! Reserved names and ranges are not exposed as descriptor collections yet.
//! Services expose ordered methods, streaming flags, options, and resolved
//! request and response message names.
//! Source-code comments are not retained in descriptors.
//! These omissions do not change binary field encoding for supported messages.
//!
//! # Error reporting
//!
//! Parser errors use byte offsets into the currently parsed source.
//! They identify missing identifiers, symbols, integers, and option values.
//! Invalid field numbers fail before a descriptor is produced.
//! Invalid map keys fail before a descriptor is produced.
//! Unterminated comments, strings, groups, and messages fail parsing.
//! Missing registry imports name the unresolved import path.
//! Duplicate imported messages and enums name the conflicting full symbol.
//! Unknown field types name both the type and resolution scope.
//! A registry intentionally does not attach filesystem paths to nested errors.
//! The caller already knows the root and registered sources being parsed.
//!
//! # Allocation behavior
//!
//! Source text is owned once by the registry.
//! Lexing creates owned token strings for identifiers and literals.
//! Descriptors own their final names and collections.
//! `BTreeMap` provides deterministic lookup without a hashing dependency.
//! Resolution creates temporary candidate-name vectors.
//! No allocation is hidden behind a global cache.
//! Dropping a registry releases its source text independently of parsed schemas.
//! Dropping a schema releases every descriptor and resolved name.
//!
//! # Compatibility tiers
//!
//! Full proto3 binary behavior is exercised by the official suite adapter.
//! Basic proto2 binary behavior uses the same dynamic descriptors and codec.
//! Basic proto2 includes ordinary scalars, messages, enums, maps, and oneofs.
//! Basic proto2 includes required-field checks and explicit packing options.
//! Declared legacy groups and MessageSet reflection are unsupported.
//! Edition 2023 syntax and its standard inherited features are implemented.
//! Typed ordinary extensions and extension ranges are resolved and validated.
//! JSON and text-format parsing belong to separate future codec layers.
//! The repository's `CONFORMANCE.md` is the authoritative support declaration.

use crate::{
    Error, Result,
    constants::{
        BOOLEAN_FALSE, BOOLEAN_TRUE, CUSTOM_OPTION_MIN_FIELD_NUMBER, EDITION_2023,
        FEATURE_ENUM_TYPE, FEATURE_FIELD_PRESENCE, FEATURE_JSON_FORMAT, FEATURE_MESSAGE_ENCODING,
        FEATURE_REPEATED_ENCODING, FEATURE_UTF8_VALIDATION, KW_EDITION, KW_ENUM, KW_EXTEND,
        KW_EXTENSIONS, KW_GROUP, KW_IMPORT, KW_MAP, KW_MAX, KW_MESSAGE, KW_ONEOF, KW_OPTION,
        KW_OPTIONAL, KW_PACKAGE, KW_PUBLIC, KW_REPEATED, KW_REQUIRED, KW_RESERVED, KW_RETURNS,
        KW_RPC, KW_SERVICE, KW_STREAM, KW_SYNTAX, KW_TO, KW_WEAK, LONG_UNICODE_ESCAPE_DIGITS,
        MAX_FIELD_NUMBER, MIN_FIELD_NUMBER, OPTION_ALLOW_ALIAS, OPTION_DEFAULT, OPTION_PACKED,
        RESERVED_FIELD_NUMBER_END, RESERVED_FIELD_NUMBER_START, SHORT_UNICODE_ESCAPE_DIGITS,
        SYNTAX_PROTO2, SYNTAX_PROTO3, TYPE_BOOL, TYPE_BYTES, TYPE_DOUBLE, TYPE_FIXED32,
        TYPE_FIXED64, TYPE_FLOAT, TYPE_INT32, TYPE_INT64, TYPE_SFIXED32, TYPE_SFIXED64,
        TYPE_SINT32, TYPE_SINT64, TYPE_STRING, TYPE_UINT32, TYPE_UINT64,
    },
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use pest::{Parser as _, error::InputLocation};

/// Pest-generated parser for the checked-in proto2/proto3/Edition grammar.
#[derive(pest_derive::Parser)]
#[grammar = "proto.pest"]
struct ProtoSyntaxParser;

/// Converts a Pest diagnostic into the crate's stable offset-bearing error.
fn pest_error(error: pest::error::Error<Rule>) -> Error {
    let offset = match error.location {
        InputLocation::Pos(offset) | InputLocation::Span((offset, _)) => offset,
    };
    Error::new(offset, error.to_string())
}

/// Validates the complete source against the formal Pest grammar.
fn validate_pest_syntax(source: &str) -> Result<()> {
    ProtoSyntaxParser::parse(Rule::proto_file, source)
        .map(|_| ())
        .map_err(pest_error)
}

/// Protobuf source-language edition supported by a parsed schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Syntax {
    /// Protocol Buffers version 2 syntax.
    Proto2,
    /// Protocol Buffers version 3 syntax.
    Proto3,
    /// Protocol Buffers Edition 2023 source and default feature set.
    Edition2023,
}

impl Syntax {
    /// Returns whether this language version uses proto3-like defaults.
    const fn has_modern_defaults(self) -> bool {
        matches!(self, Self::Proto3 | Self::Edition2023)
    }

    /// Returns whether source labels are governed by Editions rules.
    const fn is_edition(self) -> bool {
        matches!(self, Self::Edition2023)
    }
}

/// Resolved singular-field presence behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldPresence {
    /// Singular scalar fields track presence.
    Explicit,
    /// Singular scalar fields use default-value elision.
    Implicit,
    /// Absence is a message initialization error.
    LegacyRequired,
}

/// Resolved handling of numeric values absent from an enum declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnumType {
    /// Unknown numeric values remain values of the enum field.
    Open,
    /// Unknown numeric values belong to the unknown-field set.
    Closed,
}

/// Resolved wire representation for repeated packable primitives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepeatedFieldEncoding {
    /// Emit one length-delimited packed occurrence.
    Packed,
    /// Emit one ordinary occurrence per element.
    Expanded,
}

/// Resolved wire representation for embedded messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageEncoding {
    /// Emit an ordinary length-delimited message.
    LengthPrefixed,
    /// Emit matching start-group and end-group tags.
    Delimited,
}

/// Resolved validation behavior for protobuf string fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Utf8Validation {
    /// Reject wire strings that are not valid UTF-8.
    Verify,
    /// Preserve string payloads without UTF-8 validation.
    None,
}

/// Resolved JSON availability for a declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonFormat {
    /// JSON serialization is permitted.
    Allow,
    /// JSON serialization is deliberately disabled.
    LegacyBestEffort,
}

/// Inherited protobuf language features resolved for a descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureSet {
    /// Singular-field presence behavior.
    pub field_presence: FieldPresence,
    /// Enum openness behavior.
    pub enum_type: EnumType,
    /// Default repeated primitive encoding.
    pub repeated_field_encoding: RepeatedFieldEncoding,
    /// Embedded-message encoding.
    pub message_encoding: MessageEncoding,
    /// String payload validation.
    pub utf8_validation: Utf8Validation,
    /// JSON availability.
    pub json_format: JsonFormat,
}

impl FeatureSet {
    /// Returns the defaults associated with a source language version.
    pub const fn for_syntax(syntax: Syntax) -> Self {
        match syntax {
            Syntax::Proto2 => Self {
                field_presence: FieldPresence::Explicit,
                enum_type: EnumType::Closed,
                repeated_field_encoding: RepeatedFieldEncoding::Expanded,
                message_encoding: MessageEncoding::LengthPrefixed,
                utf8_validation: Utf8Validation::Verify,
                json_format: JsonFormat::LegacyBestEffort,
            },
            Syntax::Proto3 => Self {
                field_presence: FieldPresence::Implicit,
                enum_type: EnumType::Open,
                repeated_field_encoding: RepeatedFieldEncoding::Packed,
                message_encoding: MessageEncoding::LengthPrefixed,
                utf8_validation: Utf8Validation::Verify,
                json_format: JsonFormat::Allow,
            },
            Syntax::Edition2023 => Self {
                field_presence: FieldPresence::Explicit,
                enum_type: EnumType::Open,
                repeated_field_encoding: RepeatedFieldEncoding::Packed,
                message_encoding: MessageEncoding::LengthPrefixed,
                utf8_validation: Utf8Validation::Verify,
                json_format: JsonFormat::Allow,
            },
        }
    }
}
/// Declared occurrence rule for a protobuf field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cardinality {
    /// Field may occur zero or one time semantically.
    Optional,
    /// Proto2 field must be present.
    Required,
    /// Field may contain an ordered sequence of values.
    Repeated,
}
/// Resolved protobuf field type used by the dynamic codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldType {
    /// IEEE-754 double-precision value.
    Double,
    /// IEEE-754 single-precision value.
    Float,
    /// Signed 32-bit varint.
    Int32,
    /// Signed 64-bit varint.
    Int64,
    /// Unsigned 32-bit varint.
    Uint32,
    /// Unsigned 64-bit varint.
    Uint64,
    /// Zig-zag encoded signed 32-bit integer.
    Sint32,
    /// Zig-zag encoded signed 64-bit integer.
    Sint64,
    /// Little-endian fixed-width unsigned 32-bit integer.
    Fixed32,
    /// Little-endian fixed-width unsigned 64-bit integer.
    Fixed64,
    /// Little-endian fixed-width signed 32-bit integer.
    Sfixed32,
    /// Little-endian fixed-width signed 64-bit integer.
    Sfixed64,
    /// Boolean varint.
    Bool,
    /// UTF-8 string.
    String,
    /// Opaque byte string.
    Bytes,
    /// Embedded message identified by its resolved full name.
    Message(String),
    /// Enumeration identified by its resolved full name.
    Enum(String),
    /// Synthetic map entry containing its key and value types.
    Map(Box<FieldType>, Box<FieldType>),
}
/// Runtime descriptor for one protobuf message field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    /// Source-level field name.
    pub name: String,
    /// Positive numeric protobuf tag.
    pub number: u32,
    /// Optional, required, or repeated occurrence rule.
    pub cardinality: Cardinality,
    /// Resolved field value type.
    pub kind: FieldType,
    /// Explicit or syntax-derived packed-encoding setting.
    pub packed: Option<bool>,
    /// Whether `packed` was written explicitly instead of derived from syntax.
    pub packed_explicit: bool,
    /// Containing oneof name when this field is a oneof member.
    pub oneof: Option<String>,
    /// Whether this singular field has explicit presence (`optional`,
    /// `required`, a oneof member, or a message field).
    pub explicit_presence: bool,
    /// Raw proto2 default literal, retained for reflection and auditing.
    pub default: Option<String>,
    /// Source options retained in declaration order.
    pub options: Vec<OptionSetting>,
    /// Fully inherited feature values controlling this field's semantics.
    pub features: FeatureSet,
}
/// Runtime descriptor for one protobuf message declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageDescriptor {
    /// Unqualified source-level message name.
    pub name: String,
    /// Package- and nesting-qualified message name.
    pub full_name: String,
    /// Fields in declaration order.
    pub fields: Vec<Field>,
    /// Inclusive numeric ranges in which extension fields may be declared.
    pub extension_ranges: Vec<(u32, u32)>,
    /// Oneof declarations in source order, including their options.
    pub oneofs: Vec<OneofDescriptor>,
    /// Message options retained for reflection and semantic auditing.
    pub options: Vec<OptionSetting>,
    /// Fully inherited feature values controlling this message.
    pub features: FeatureSet,
}
impl MessageDescriptor {
    /// Finds a field descriptor by its numeric protobuf tag.
    pub fn field_by_number(&self, number: u32) -> Option<&Field> {
        self.fields.iter().find(|field| field.number == number)
    }
    /// Finds a field descriptor by its source-level protobuf name.
    pub fn field_by_name(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
    }
}
impl Field {
    /// Returns the protobuf JSON name, honoring an explicit `json_name` option.
    pub fn json_name(&self) -> String {
        field_json_name(self)
    }
}
/// One named numeric member of a protobuf enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumValue {
    /// Source-level enum member name.
    pub name: String,
    /// Signed numeric enum value.
    pub number: i32,
    /// Enum-value options retained for semantic auditing.
    pub options: Vec<OptionSetting>,
}
/// Runtime descriptor for a protobuf enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enum {
    /// Unqualified source-level enum name.
    pub name: String,
    /// Package- and nesting-qualified enum name.
    pub full_name: String,
    /// Declared enumeration members.
    pub values: Vec<EnumValue>,
    /// Syntax of the file that declares this enumeration.
    pub syntax: Syntax,
    /// Enum options retained for reflection and semantic auditing.
    pub options: Vec<OptionSetting>,
    /// Fully inherited feature values controlling this enum.
    pub features: FeatureSet,
}
/// One source-level protobuf option after lexical normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptionSetting {
    /// Built-in name or parenthesized custom-option name.
    pub name: String,
    /// Scalar or aggregate source value without surrounding whitespace.
    pub value: String,
    /// Lexical category used for built-in option type validation.
    pub value_kind: OptionValueKind,
}
/// Lexical category of a protobuf option value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionValueKind {
    /// Identifier value, including booleans and enum member names.
    Identifier,
    /// One or more adjacent quoted string literals.
    String,
    /// Integer or floating-point numeric literal.
    Number,
    /// Braced aggregate message value.
    Aggregate,
}
/// One oneof declaration and its retained source options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneofDescriptor {
    /// Source-level oneof name.
    pub name: String,
    /// Oneof options retained for reflection and validation.
    pub options: Vec<OptionSetting>,
}
/// One RPC method retained from a proto3 service declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodDescriptor {
    /// Method name within its containing service.
    pub name: String,
    /// Fully resolved protobuf request message name.
    pub input_type: String,
    /// Fully resolved protobuf response message name.
    pub output_type: String,
    /// Whether the request side is client-streaming.
    pub client_streaming: bool,
    /// Whether the response side is server-streaming.
    pub server_streaming: bool,
    /// Method options retained for reflection and semantic auditing.
    pub options: Vec<OptionSetting>,
}
/// Runtime descriptor for a protobuf service declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceDescriptor {
    /// Unqualified source-level service name.
    pub name: String,
    /// Package-qualified service name.
    pub full_name: String,
    /// RPC methods in source declaration order.
    pub methods: Vec<MethodDescriptor>,
    /// Service options retained for reflection and semantic auditing.
    pub options: Vec<OptionSetting>,
}
/// Proto3 extension field that defines a custom descriptor option.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomOptionDescriptor {
    /// Unqualified extension field name.
    pub name: String,
    /// Package- and nesting-qualified extension name.
    pub full_name: String,
    /// Descriptor options message extended by this declaration.
    pub extendee: String,
    /// Field metadata describing the option's value and cardinality.
    pub field: Field,
}
/// Typed field declared outside its extended message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionDescriptor {
    /// Package- and scope-qualified extension field name.
    pub full_name: String,
    /// Fully resolved message receiving this extension.
    pub extendee: String,
    /// Resolved field metadata used by the dynamic codec.
    pub field: Field,
}
/// Import modifier attached to a protobuf import declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportKind {
    /// Required ordinary import.
    Normal,
    /// Required import whose declarations are re-exported to importers.
    Public,
    /// Optional import that may be absent from the registry.
    Weak,
}
/// Parsed protobuf import declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Import {
    /// Logical registry path named by the import.
    pub path: String,
    /// Import modifier controlling resolution behavior.
    pub kind: ImportKind,
}
/// Fully parsed and type-resolved collection of protobuf declarations.
#[derive(Clone, Debug)]
pub struct Schema {
    /// Syntax declared by the root source.
    pub syntax: Syntax,
    /// Optional package declared by the root source.
    pub package: Option<String>,
    /// Message descriptors indexed by fully qualified name.
    pub messages: BTreeMap<String, MessageDescriptor>,
    /// Enum descriptors indexed by fully qualified name.
    pub enums: BTreeMap<String, Enum>,
    /// Service descriptors indexed by fully qualified name.
    pub services: BTreeMap<String, ServiceDescriptor>,
    /// Custom option extensions indexed by fully qualified extension name.
    pub custom_options: BTreeMap<String, CustomOptionDescriptor>,
    /// Ordinary typed extensions indexed by qualified extension name.
    pub extensions: BTreeMap<String, ExtensionDescriptor>,
    /// Import declarations collected from all reachable sources.
    pub imports: Vec<Import>,
    /// Root-file options retained for reflection and semantic auditing.
    pub options: Vec<OptionSetting>,
    /// Resolved root-file feature values.
    pub features: FeatureSet,
}

/// An allocation-backed collection of named `.proto` sources.
///
/// The registry is the only import resolver used by this crate. Applications
/// load files, flash-resident strings, network resources, or generated schema
/// text into it before parsing. The parser itself never performs I/O, which is
/// essential for the crate's `no_std` contract.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    sources: BTreeMap<String, String>,
}

impl Registry {
    /// Creates an empty schema registry.
    pub const fn new() -> Self {
        Self {
            sources: BTreeMap::new(),
        }
    }

    /// Registers or replaces a source under its protobuf import path.
    ///
    /// The path must match the text used by importing schemas. Returns the
    /// previously registered source when the path is replaced.
    pub fn register(
        &mut self,
        path: impl Into<String>,
        source: impl Into<String>,
    ) -> Option<String> {
        self.sources.insert(path.into(), source.into())
    }

    /// Returns the source registered for an exact protobuf import path.
    pub fn source(&self, path: &str) -> Option<&str> {
        self.sources.get(path).map(String::as_str)
    }

    /// Parses a registered root and every transitively imported schema.
    ///
    /// `root` is a logical registry path, not a filesystem path. Only sources
    /// reachable from that root are included in the returned descriptor set.
    ///
    /// # Errors
    ///
    /// Returns an error when a required source is absent, a source is invalid,
    /// imported declarations conflict, or a referenced type cannot be resolved.
    pub fn parse(&self, root: &str) -> Result<Schema> {
        parse_registry(root, self)
    }

    /// Reports how many source files are currently registered.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Reports whether no sources have been registered yet.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}
impl Schema {
    /// Finds a regular or typed extension field by message and numeric tag.
    pub fn field_by_number<'a>(
        &'a self,
        message: &'a MessageDescriptor,
        number: u32,
    ) -> Option<&'a Field> {
        message.field_by_number(number).or_else(|| {
            self.extensions
                .values()
                .find(|extension| {
                    extension.extendee == message.full_name && extension.field.number == number
                })
                .map(|extension| &extension.field)
        })
    }

    /// Iterates regular fields followed by typed extensions for a message.
    pub fn fields_for<'a>(
        &'a self,
        message: &'a MessageDescriptor,
    ) -> impl Iterator<Item = &'a Field> {
        message.fields.iter().chain(
            self.extensions
                .values()
                .filter(move |extension| extension.extendee == message.full_name)
                .map(|extension| &extension.field),
        )
    }

    /// Looks up a message by fully qualified name or by this schema's package.
    ///
    /// Exact full-name lookup is attempted first. If it fails and the root
    /// schema declares a package, that package is prepended to `name`.
    pub fn message(&self, name: &str) -> Option<&MessageDescriptor> {
        self.messages.get(name).or_else(|| {
            self.package
                .as_ref()
                .and_then(|package| self.messages.get(&format!("{package}.{name}")))
        })
    }
    /// Looks up a service by fully qualified name or the root package.
    pub fn service(&self, name: &str) -> Option<&ServiceDescriptor> {
        self.services.get(name).or_else(|| {
            self.package
                .as_ref()
                .and_then(|package| self.services.get(&format!("{package}.{name}")))
        })
    }
}
/// Lexical unit retained by the schema parser together with its source offset.
#[derive(Clone)]
enum Token {
    /// Identifier, keyword, or qualified protobuf name.
    Identifier(String),
    /// Contents of a single- or double-quoted literal without delimiters.
    StringLiteral(String),
    /// Numeric-looking text whose interpretation depends on grammar position.
    NumberLiteral(String),
    /// One punctuation character.
    Symbol(char),
}

/// Returns whether `value` is one unqualified protobuf identifier.
fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Returns whether `value` is a valid dot-qualified protobuf identifier.
fn is_full_identifier(value: &str, allow_leading_dot: bool) -> bool {
    let value = if allow_leading_dot {
        value.strip_prefix('.').unwrap_or(value)
    } else {
        value
    };
    !value.is_empty() && value.split('.').all(is_identifier)
}

/// Reserved names and inclusive numeric ranges collected while parsing a body.
#[derive(Default)]
struct ReservedDeclarations {
    names: Vec<String>,
    ranges: Vec<(i64, i64)>,
}

/// Rejects Unicode escapes that do not identify a Unicode scalar value.
///
/// Pest verifies escape spelling and digit counts. This semantic pass handles
/// the scalar-value constraint, including surrogate code points and values
/// above the Unicode maximum.
fn validate_unicode_escapes(value: &str, offset: usize) -> Result<()> {
    let bytes = value.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes.get(cursor) != Some(&b'\\') {
            cursor += 1;
            continue;
        }
        let escape = bytes
            .get(cursor + 1)
            .ok_or_else(|| Error::new(offset, "truncated string escape"))?;
        let digits = match escape {
            b'u' => SHORT_UNICODE_ESCAPE_DIGITS,
            b'U' => LONG_UNICODE_ESCAPE_DIGITS,
            _ => {
                cursor += 2;
                continue;
            }
        };
        let digits_start = cursor + 2;
        let digits_end = digits_start
            .checked_add(digits)
            .ok_or_else(|| Error::new(offset, "Unicode escape length overflow"))?;
        let hexadecimal = value
            .get(digits_start..digits_end)
            .ok_or_else(|| Error::new(offset, "truncated Unicode escape"))?;
        let code_point = u32::from_str_radix(hexadecimal, 16)
            .map_err(|_| Error::new(offset, "invalid Unicode escape"))?;
        if char::from_u32(code_point).is_none() {
            return Err(Error::new(offset, "invalid Unicode scalar value"));
        }
        cursor = digits_end;
    }
    Ok(())
}

/// Produces descriptor-builder tokens from Pest's grammar-derived token stream.
///
/// Pest discards comments and whitespace and retains byte spans for precise
/// semantic diagnostics. String delimiters are removed, but escape spelling is
/// preserved so defaults can be audited without lossy normalization.
fn lex(source: &str) -> Result<Vec<(Token, usize)>> {
    let mut parsed = ProtoSyntaxParser::parse(Rule::token_stream, source).map_err(pest_error)?;
    let stream = parsed
        .next()
        .ok_or_else(|| Error::new(0, "Pest returned no token stream"))?;
    let mut tokens = Vec::new();
    for pair in stream.into_inner() {
        let offset = pair.as_span().start();
        let text = pair.as_str();
        let token = match pair.as_rule() {
            Rule::lex_identifier => Token::Identifier(text.to_string()),
            Rule::lex_number => Token::NumberLiteral(text.to_string()),
            Rule::string_literal => {
                let end = text
                    .len()
                    .checked_sub(1)
                    .ok_or_else(|| Error::new(offset, "invalid Pest string span"))?;
                let contents = text
                    .get(1..end)
                    .ok_or_else(|| Error::new(offset, "invalid Pest string boundary"))?;
                validate_unicode_escapes(contents, offset)?;
                Token::StringLiteral(contents.to_string())
            }
            Rule::lex_symbol => {
                let symbol = text
                    .chars()
                    .next()
                    .ok_or_else(|| Error::new(offset, "empty Pest symbol span"))?;
                Token::Symbol(symbol)
            }
            Rule::EOI => continue,
            _ => return Err(Error::new(offset, "unexpected Pest token rule")),
        };
        tokens.push((token, offset));
    }
    Ok(tokens)
}
/// Mutable semantic descriptor-builder state for one protobuf source file.
struct DescriptorBuilder {
    /// Lexed tokens paired with byte offsets into the source.
    tokens: Vec<(Token, usize)>,
    /// Index of the next token to consume.
    cursor: usize,
    /// Syntax controlling default packing and field-presence behavior.
    syntax: Syntax,
    /// Package applied to top-level declarations in this source.
    package: Option<String>,
    /// Message descriptors accumulated by fully qualified name.
    messages: BTreeMap<String, MessageDescriptor>,
    /// Enum descriptors accumulated by fully qualified name.
    enums: BTreeMap<String, Enum>,
    /// Service descriptors accumulated by fully qualified name.
    services: BTreeMap<String, ServiceDescriptor>,
    /// Custom option extensions accumulated by fully qualified name.
    custom_options: BTreeMap<String, CustomOptionDescriptor>,
    /// Ordinary message extensions accumulated by qualified field name.
    extensions: BTreeMap<String, ExtensionDescriptor>,
    /// Import declarations retained for registry graph traversal.
    imports: Vec<Import>,
    /// File options retained in source order.
    options: Vec<OptionSetting>,
}
impl DescriptorBuilder {
    /// Returns the current token's source offset, or zero at end of input.
    fn offset(&self) -> usize {
        self.tokens
            .get(self.cursor)
            .map(|token| token.1)
            .unwrap_or(0)
    }
    /// Reports whether the current token is the specified identifier.
    fn peek_identifier(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.cursor),Some((Token::Identifier(value),_))if value==expected)
    }
    /// Reports whether the current token is the specified punctuation symbol.
    fn peek_symbol(&self, expected: char) -> bool {
        matches!(self.tokens.get(self.cursor),Some((Token::Symbol(value),_))if *value==expected)
    }
    /// Consumes an identifier or reports its source location as an error.
    fn identifier(&mut self) -> Result<String> {
        match self.tokens.get(self.cursor).cloned() {
            Some((Token::Identifier(value), _)) => {
                self.cursor += 1;
                Ok(value)
            }
            _ => Err(Error::new(self.offset(), "expected identifier")),
        }
    }
    /// Consumes a simple declaration name and rejects qualified identifiers.
    fn declaration_name(&mut self) -> Result<String> {
        let offset = self.offset();
        let name = self.identifier()?;
        if is_identifier(&name) {
            Ok(name)
        } else {
            Err(Error::new(offset, "invalid protobuf identifier"))
        }
    }
    /// Consumes a package name and validates every dot-separated component.
    fn package_name(&mut self) -> Result<String> {
        let offset = self.offset();
        let name = self.identifier()?;
        if is_full_identifier(&name, false) {
            Ok(name)
        } else {
            Err(Error::new(offset, "invalid protobuf package name"))
        }
    }
    /// Consumes and parses an integer token.
    fn integer(&mut self) -> Result<i64> {
        match self.tokens.get(self.cursor).cloned() {
            Some((Token::NumberLiteral(value), offset)) => {
                self.cursor += 1;
                let (negative, unsigned) = value
                    .strip_prefix('-')
                    .map_or((false, value.as_str()), |value| (true, value));
                let unsigned = unsigned.strip_prefix('+').unwrap_or(unsigned);
                let (digits, radix) = if let Some(digits) = unsigned
                    .strip_prefix("0x")
                    .or_else(|| unsigned.strip_prefix("0X"))
                {
                    (digits, 16)
                } else if unsigned.len() > 1 && unsigned.starts_with('0') {
                    (unsigned, 8)
                } else {
                    (unsigned, 10)
                };
                let magnitude = i128::from_str_radix(digits, radix)
                    .map_err(|_| Error::new(offset, "expected integer"))?;
                let signed = if negative {
                    magnitude
                        .checked_neg()
                        .ok_or_else(|| Error::new(offset, "integer is out of range"))?
                } else {
                    magnitude
                };
                i64::try_from(signed).map_err(|_| Error::new(offset, "integer is out of range"))
            }
            _ => Err(Error::new(self.offset(), "expected integer")),
        }
    }
    /// Consumes the requested punctuation symbol.
    fn expect_symbol(&mut self, expected: char) -> Result<()> {
        if matches!(self.tokens.get(self.cursor),Some((Token::Symbol(value),_))if *value==expected)
        {
            self.cursor += 1;
            Ok(())
        } else {
            Err(Error::new(self.offset(), format!("expected '{expected}'")))
        }
    }
    /// Consumes a punctuation symbol when present and reports whether it matched.
    fn consume_symbol(&mut self, expected: char) -> bool {
        self.expect_symbol(expected).is_ok()
    }
    /// Qualifies a declared or referenced name against its lexical scope.
    fn qualify(&self, scope: &str, name: &str) -> String {
        if let Some(name) = name.strip_prefix('.') {
            name.to_string()
        } else if scope.is_empty() {
            self.package
                .as_ref()
                .map(|package| format!("{package}.{name}"))
                .unwrap_or_else(|| name.to_string())
        } else {
            format!("{scope}.{name}")
        }
    }
    /// Consumes a scalar field-option value in identifier, string, or numeric form.
    fn option_value(&mut self) -> Result<String> {
        match self.tokens.get(self.cursor).cloned() {
            Some((Token::StringLiteral(mut value), _)) => {
                self.cursor += 1;
                while let Some((Token::StringLiteral(next), _)) = self.tokens.get(self.cursor) {
                    value.push_str(next);
                    self.cursor += 1;
                }
                Ok(value)
            }
            Some((Token::Identifier(value), _)) | Some((Token::NumberLiteral(value), _)) => {
                self.cursor += 1;
                Ok(value)
            }
            _ => Err(Error::new(self.offset(), "expected option value")),
        }
    }

    /// Parses a built-in or parenthesized custom option name.
    fn option_name(&mut self) -> Result<String> {
        if !self.consume_symbol('(') {
            return self.identifier();
        }
        let extension = self.identifier()?;
        self.expect_symbol(')')?;
        let mut name = format!("({extension})");
        while let Some((Token::Identifier(component), _)) = self.tokens.get(self.cursor) {
            let Some(component) = component.strip_prefix('.') else {
                break;
            };
            if !is_identifier(component) {
                return Err(Error::new(self.offset(), "invalid custom option path"));
            }
            name.push('.');
            name.push_str(component);
            self.cursor += 1;
        }
        Ok(name)
    }

    /// Consumes an aggregate option value while preserving balanced structure.
    fn aggregate_option_value(&mut self) -> Result<String> {
        self.expect_symbol('{')?;
        let mut value = String::from("{");
        let mut depth = 1usize;
        while depth != 0 {
            let (token, _) = self
                .tokens
                .get(self.cursor)
                .cloned()
                .ok_or_else(|| Error::new(self.offset(), "unterminated aggregate option"))?;
            self.cursor += 1;
            match token {
                Token::Symbol('{') => {
                    depth += 1;
                    value.push('{');
                }
                Token::Symbol('}') => {
                    depth -= 1;
                    value.push('}');
                }
                Token::Symbol(symbol) => value.push(symbol),
                Token::Identifier(text) | Token::NumberLiteral(text) => value.push_str(&text),
                Token::StringLiteral(text) => {
                    value.push('"');
                    value.push_str(&text);
                    value.push('"');
                }
            }
        }
        Ok(value)
    }

    /// Parses one option assignment without consuming its outer delimiter.
    fn option_setting(&mut self) -> Result<OptionSetting> {
        let name = self.option_name()?;
        self.expect_symbol('=')?;
        let (value, value_kind) = if self.peek_symbol('{') {
            (self.aggregate_option_value()?, OptionValueKind::Aggregate)
        } else {
            let value_kind = match self.tokens.get(self.cursor) {
                Some((Token::StringLiteral(_), _)) => OptionValueKind::String,
                Some((Token::NumberLiteral(_), _)) => OptionValueKind::Number,
                Some((Token::Identifier(_), _)) => OptionValueKind::Identifier,
                _ => return Err(Error::new(self.offset(), "expected option value")),
            };
            (self.option_value()?, value_kind)
        };
        Ok(OptionSetting {
            name,
            value,
            value_kind,
        })
    }

    /// Parses a complete `option name = value;` declaration.
    fn option_declaration(&mut self) -> Result<OptionSetting> {
        self.identifier()?;
        let option = self.option_setting()?;
        self.expect_symbol(';')?;
        Ok(option)
    }

    /// Parses a reserved-name or reserved-number statement through its semicolon.
    fn parse_reserved(&mut self, minimum: i64, maximum: i64) -> Result<ReservedDeclarations> {
        self.identifier()?;
        let mut reserved = ReservedDeclarations::default();
        let names = matches!(
            self.tokens.get(self.cursor),
            Some((Token::StringLiteral(_), _))
        ) || (self.syntax.is_edition()
            && matches!(
                self.tokens.get(self.cursor),
                Some((Token::Identifier(_), _))
            ));
        loop {
            if names {
                let offset = self.offset();
                let name = match self.tokens.get(self.cursor).cloned() {
                    Some((Token::StringLiteral(name), _)) => {
                        self.cursor += 1;
                        name
                    }
                    Some((Token::Identifier(name), _)) if self.syntax.is_edition() => {
                        self.cursor += 1;
                        name
                    }
                    _ => return Err(Error::new(offset, "cannot mix reserved names and numbers")),
                };
                if !is_identifier(&name) {
                    return Err(Error::new(offset, "invalid reserved field name"));
                }
                reserved.names.push(name);
            } else {
                let start = self.integer()?;
                let end = if self.peek_identifier(KW_TO) {
                    self.identifier()?;
                    if self.peek_identifier(KW_MAX) {
                        self.identifier()?;
                        maximum
                    } else {
                        self.integer()?
                    }
                } else {
                    start
                };
                if start < minimum || start > end || end > maximum {
                    return Err(Error::new(self.offset(), "invalid reserved numeric range"));
                }
                reserved.ranges.push((start, end));
            }
            if !self.consume_symbol(',') {
                break;
            }
        }
        self.expect_symbol(';')?;
        Ok(reserved)
    }

    /// Parses past a legacy proto2 group declaration without describing it.
    ///
    /// The opening label, name, tag, and balanced body are validated so parsing
    /// can safely resume at the next supported field. An unclosed group fails.
    fn skip_group(&mut self) -> Result<()> {
        self.identifier()?;
        self.identifier()?;
        self.expect_symbol('=')?;
        self.integer()?;
        self.expect_symbol('{')?;
        let mut depth = 1usize;
        while depth != 0 {
            match self.tokens.get(self.cursor) {
                Some((Token::Symbol('{'), _)) => depth += 1,
                Some((Token::Symbol('}'), _)) => depth -= 1,
                Some(_) => {}
                None => return Err(Error::new(self.offset(), "unterminated group")),
            }
            self.cursor += 1;
        }
        self.consume_symbol(';');
        Ok(())
    }
    /// Parses an enum declaration and inserts its descriptor into parser state.
    ///
    /// Enum options and reserved declarations are structurally validated.
    /// Values retain declaration order and signed numeric assignments.
    fn parse_enum(&mut self, scope: &str) -> Result<()> {
        self.identifier()?;
        let name = self.declaration_name()?;
        let full_name = self.qualify(scope, &name);
        self.expect_symbol('{')?;
        let mut values = Vec::new();
        let mut reserved = ReservedDeclarations::default();
        let mut allow_alias = false;
        let mut options = Vec::new();
        while !self.consume_symbol('}') {
            if self.consume_symbol(';') {
                continue;
            }
            if self.peek_identifier(KW_RESERVED) {
                let declaration = self.parse_reserved(i64::from(i32::MIN), i64::from(i32::MAX))?;
                reserved.names.extend(declaration.names);
                reserved.ranges.extend(declaration.ranges);
                continue;
            }
            if self.peek_identifier(KW_OPTION) {
                let option = self.option_declaration()?;
                if option.name == OPTION_ALLOW_ALIAS {
                    allow_alias = match option.value.as_str() {
                        BOOLEAN_TRUE => true,
                        BOOLEAN_FALSE => false,
                        _ => {
                            return Err(Error::new(
                                self.offset(),
                                "allow_alias must be true or false",
                            ));
                        }
                    };
                }
                options.push(option);
                continue;
            }
            let value_name = self.declaration_name()?;
            self.expect_symbol('=')?;
            let raw_number = self.integer()?;
            let number = i32::try_from(raw_number)
                .map_err(|_| Error::new(self.offset(), "enum value is outside int32 range"))?;
            let mut value_options = Vec::new();
            if self.consume_symbol('[') {
                loop {
                    if self.consume_symbol(']') {
                        break;
                    }
                    value_options.push(self.option_setting()?);
                    if !self.consume_symbol(']') {
                        self.expect_symbol(',')?;
                    } else {
                        break;
                    }
                }
            }
            self.expect_symbol(';')?;
            values.push(EnumValue {
                name: value_name,
                number,
                options: value_options,
            })
        }
        if values.is_empty() {
            return Err(Error::new(
                self.offset(),
                "enum must declare at least one value",
            ));
        }
        if self.syntax.has_modern_defaults()
            && values.first().is_some_and(|value| value.number != 0)
        {
            return Err(Error::new(
                self.offset(),
                "first proto3 enum value must be zero",
            ));
        }
        validate_reserved_declarations(&reserved, self.offset())?;
        for (index, value) in values.iter().enumerate() {
            if values[..index]
                .iter()
                .any(|previous| previous.name == value.name)
            {
                return Err(Error::new(self.offset(), "duplicate enum value name"));
            }
            if !allow_alias
                && values[..index]
                    .iter()
                    .any(|previous| previous.number == value.number)
            {
                return Err(Error::new(
                    self.offset(),
                    "duplicate enum number requires allow_alias = true",
                ));
            }
            if reserved.names.iter().any(|name| name == &value.name)
                || reserved
                    .ranges
                    .iter()
                    .any(|(start, end)| (*start..=*end).contains(&i64::from(value.number)))
            {
                return Err(Error::new(
                    self.offset(),
                    "enum value uses a reserved name or number",
                ));
            }
        }
        if self.messages.contains_key(&full_name) || self.enums.contains_key(&full_name) {
            return Err(Error::new(self.offset(), "duplicate protobuf type name"));
        }
        self.enums.insert(
            full_name.clone(),
            Enum {
                name,
                full_name,
                values,
                syntax: self.syntax,
                options,
                features: FeatureSet::for_syntax(self.syntax),
            },
        );
        Ok(())
    }
    /// Parses a message and its nested declarations into descriptor state.
    ///
    /// Nested messages and enums recurse with the message's full name as their
    /// scope. Oneof members receive their shared group name during field parsing.
    fn parse_message(&mut self, scope: &str) -> Result<()> {
        self.identifier()?;
        let name = self.declaration_name()?;
        let full_name = self.qualify(scope, &name);
        self.expect_symbol('{')?;
        let mut fields = Vec::new();
        let mut oneofs = Vec::<OneofDescriptor>::new();
        let mut reserved = ReservedDeclarations::default();
        let mut extension_ranges = Vec::new();
        let mut options = Vec::new();
        while !self.consume_symbol('}') {
            if self.consume_symbol(';') {
                continue;
            }
            if self.peek_identifier(KW_MESSAGE) {
                self.parse_message(&full_name)?;
                continue;
            }
            if self.peek_identifier(KW_ENUM) {
                self.parse_enum(&full_name)?;
                continue;
            }
            if self.peek_identifier(KW_ONEOF) {
                self.identifier()?;
                let oneof_name = self.declaration_name()?;
                if oneofs.iter().any(|oneof| oneof.name == oneof_name) {
                    return Err(Error::new(self.offset(), "duplicate oneof name"));
                }
                self.expect_symbol('{')?;
                let mut oneof_options = Vec::new();
                while !self.consume_symbol('}') {
                    if self.consume_symbol(';') {
                        continue;
                    }
                    if self.peek_identifier(KW_OPTION) {
                        oneof_options.push(self.option_declaration()?);
                        continue;
                    }
                    fields.push(self.parse_field(Some(oneof_name.clone()), None)?)
                }
                oneofs.push(OneofDescriptor {
                    name: oneof_name,
                    options: oneof_options,
                });
                continue;
            }
            if self.peek_identifier(KW_RESERVED) {
                let declaration =
                    self.parse_reserved(i64::from(MIN_FIELD_NUMBER), i64::from(MAX_FIELD_NUMBER))?;
                reserved.names.extend(declaration.names);
                reserved.ranges.extend(declaration.ranges);
                continue;
            }
            if self.peek_identifier(KW_OPTION) {
                options.push(self.option_declaration()?);
                continue;
            }
            if self.peek_identifier(KW_EXTEND) {
                self.parse_custom_option_extensions(&full_name)?;
                continue;
            }
            if self.peek_identifier(KW_EXTENSIONS) {
                if self.syntax == Syntax::Proto3 {
                    return Err(Error::new(
                        self.offset(),
                        "proto3 extensions are permitted only for custom options",
                    ));
                }
                let declaration =
                    self.parse_reserved(i64::from(MIN_FIELD_NUMBER), i64::from(MAX_FIELD_NUMBER))?;
                for (start, end) in declaration.ranges {
                    extension_ranges.push((start as u32, end as u32));
                }
                continue;
            }
            let cardinality = if self.peek_identifier(KW_REQUIRED) {
                if self.syntax.is_edition() {
                    return Err(Error::new(
                        self.offset(),
                        "required labels are not used in Editions",
                    ));
                }
                self.identifier()?;
                Some(Cardinality::Required)
            } else if self.peek_identifier(KW_OPTIONAL) {
                if self.syntax.is_edition() {
                    return Err(Error::new(
                        self.offset(),
                        "optional labels are not used in Editions",
                    ));
                }
                self.identifier()?;
                Some(Cardinality::Optional)
            } else if self.peek_identifier(KW_REPEATED) {
                self.identifier()?;
                Some(Cardinality::Repeated)
            } else {
                None
            };
            if self.peek_identifier(KW_GROUP) {
                if self.syntax == Syntax::Proto3 {
                    return Err(Error::new(
                        self.offset(),
                        "groups are not allowed in proto3",
                    ));
                }
                self.skip_group()?;
                continue;
            }
            fields.push(self.parse_field(None, cardinality)?)
        }
        let oneof_names: Vec<String> = oneofs.iter().map(|oneof| oneof.name.clone()).collect();
        validate_message_fields(&fields, &oneof_names, &reserved, self.offset())?;
        if self.syntax.has_modern_defaults() {
            validate_json_field_names(&fields, self.offset())?;
        }
        if self.messages.contains_key(&full_name) || self.enums.contains_key(&full_name) {
            return Err(Error::new(self.offset(), "duplicate protobuf type name"));
        }
        self.messages.insert(
            full_name.clone(),
            MessageDescriptor {
                name,
                full_name,
                fields,
                extension_ranges,
                oneofs,
                options,
                features: FeatureSet::for_syntax(self.syntax),
            },
        );
        Ok(())
    }

    /// Parses custom-option or ordinary typed extension declarations.
    fn parse_custom_option_extensions(&mut self, scope: &str) -> Result<()> {
        self.identifier()?;
        let extendee = self.identifier()?;
        let extendee = extendee.trim_start_matches('.').to_string();
        let custom_option = is_custom_option_extendee(&extendee);
        if !custom_option && self.syntax == Syntax::Proto3 {
            return Err(Error::new(
                self.offset(),
                "proto3 extend target must be a descriptor options message",
            ));
        }
        self.expect_symbol('{')?;
        while !self.consume_symbol('}') {
            if self.consume_symbol(';') {
                continue;
            }
            let cardinality = if self.peek_identifier(KW_OPTIONAL) {
                if self.syntax.is_edition() {
                    return Err(Error::new(
                        self.offset(),
                        "optional labels are not used in Editions",
                    ));
                }
                self.identifier()?;
                Cardinality::Optional
            } else if self.peek_identifier(KW_REPEATED) {
                self.identifier()?;
                Cardinality::Repeated
            } else if self.peek_identifier(KW_REQUIRED) {
                if self.syntax.has_modern_defaults() {
                    return Err(Error::new(
                        self.offset(),
                        "required extension fields are not allowed here",
                    ));
                }
                self.identifier()?;
                Cardinality::Required
            } else {
                Cardinality::Optional
            };
            if self.peek_identifier(KW_GROUP) {
                self.skip_group()?;
                continue;
            }
            let mut field = self.parse_field(None, Some(cardinality))?;
            if custom_option && field.number < CUSTOM_OPTION_MIN_FIELD_NUMBER {
                return Err(Error::new(
                    self.offset(),
                    "custom option number is outside the descriptor extension range",
                ));
            }
            let full_name = self.qualify(scope, &field.name);
            if custom_option
                && (self.custom_options.contains_key(&full_name)
                    || self.custom_options.values().any(|option| {
                        option.extendee == extendee && option.field.number == field.number
                    }))
            {
                return Err(Error::new(
                    self.offset(),
                    "duplicate custom option name or number",
                ));
            }
            if custom_option {
                self.custom_options.insert(
                    full_name.clone(),
                    CustomOptionDescriptor {
                        name: field.name.clone(),
                        full_name,
                        extendee: extendee.clone(),
                        field,
                    },
                );
            } else {
                if self.extensions.contains_key(&full_name) {
                    return Err(Error::new(
                        self.offset(),
                        "duplicate extension name or number",
                    ));
                }
                field.name = full_name.clone();
                self.extensions.insert(
                    full_name.clone(),
                    ExtensionDescriptor {
                        full_name,
                        extendee: extendee.clone(),
                        field,
                    },
                );
            }
        }
        Ok(())
    }

    /// Parses a proto3 service and retains resolved RPC-facing metadata.
    fn parse_service(&mut self) -> Result<()> {
        self.identifier()?;
        let name = self.declaration_name()?;
        let full_name = self.qualify("", &name);
        self.expect_symbol('{')?;
        let mut methods = Vec::new();
        let mut options = Vec::new();
        while !self.consume_symbol('}') {
            if self.consume_symbol(';') {
                continue;
            }
            if self.peek_identifier(KW_OPTION) {
                options.push(self.option_declaration()?);
                continue;
            }
            if !self.peek_identifier(KW_RPC) {
                return Err(Error::new(self.offset(), "expected service option or rpc"));
            }
            self.identifier()?;
            let method_name = self.declaration_name()?;
            if methods
                .iter()
                .any(|method: &MethodDescriptor| method.name == method_name)
            {
                return Err(Error::new(self.offset(), "duplicate rpc method name"));
            }
            self.expect_symbol('(')?;
            let client_streaming = if self.peek_identifier(KW_STREAM) {
                self.identifier()?;
                true
            } else {
                false
            };
            let input_type = self.identifier()?;
            if !is_full_identifier(&input_type, true) {
                return Err(Error::new(self.offset(), "invalid rpc request type"));
            }
            self.expect_symbol(')')?;
            if !self.peek_identifier(KW_RETURNS) {
                return Err(Error::new(
                    self.offset(),
                    "expected returns in rpc declaration",
                ));
            }
            self.identifier()?;
            self.expect_symbol('(')?;
            let server_streaming = if self.peek_identifier(KW_STREAM) {
                self.identifier()?;
                true
            } else {
                false
            };
            let output_type = self.identifier()?;
            if !is_full_identifier(&output_type, true) {
                return Err(Error::new(self.offset(), "invalid rpc response type"));
            }
            self.expect_symbol(')')?;
            let mut method_options = Vec::new();
            if !self.consume_symbol(';') {
                self.expect_symbol('{')?;
                while !self.consume_symbol('}') {
                    if self.consume_symbol(';') {
                        continue;
                    }
                    if !self.peek_identifier(KW_OPTION) {
                        return Err(Error::new(self.offset(), "expected rpc option"));
                    }
                    method_options.push(self.option_declaration()?);
                }
            }
            methods.push(MethodDescriptor {
                name: method_name,
                input_type,
                output_type,
                client_streaming,
                server_streaming,
                options: method_options,
            });
        }
        if self.services.contains_key(&full_name) {
            return Err(Error::new(self.offset(), "duplicate service name"));
        }
        self.services.insert(
            full_name.clone(),
            ServiceDescriptor {
                name,
                full_name,
                methods,
                options,
            },
        );
        Ok(())
    }

    /// Parses and validates one ordinary, oneof, or map field declaration.
    ///
    /// This enforces legal map key types and field-number ranges, extracts the
    /// supported `packed` and `default` options, and computes initial presence
    /// and packing metadata. User-defined types are resolved in a later pass.
    fn parse_field(
        &mut self,
        oneof: Option<String>,
        declared_cardinality: Option<Cardinality>,
    ) -> Result<Field> {
        let is_map = self.peek_identifier(KW_MAP);
        if self.syntax == Syntax::Proto2
            && declared_cardinality.is_none()
            && oneof.is_none()
            && !is_map
        {
            return Err(Error::new(
                self.offset(),
                "proto2 field requires a cardinality label",
            ));
        }
        if self.syntax.has_modern_defaults() && declared_cardinality == Some(Cardinality::Required)
        {
            return Err(Error::new(
                self.offset(),
                "required fields are not allowed in proto3",
            ));
        }
        if is_map && (declared_cardinality.is_some() || oneof.is_some()) {
            return Err(Error::new(
                self.offset(),
                "map fields cannot have labels or belong to oneof",
            ));
        }
        let kind = if is_map {
            self.identifier()?;
            self.expect_symbol('<')?;
            let key_type = self.parse_type()?;
            self.expect_symbol(',')?;
            let value_type = self.parse_type()?;
            self.expect_symbol('>')?;
            if !matches!(
                key_type,
                FieldType::Int32
                    | FieldType::Int64
                    | FieldType::Uint32
                    | FieldType::Uint64
                    | FieldType::Sint32
                    | FieldType::Sint64
                    | FieldType::Fixed32
                    | FieldType::Fixed64
                    | FieldType::Sfixed32
                    | FieldType::Sfixed64
                    | FieldType::Bool
                    | FieldType::String
            ) {
                return Err(Error::new(self.offset(), "invalid protobuf map key type"));
            }
            FieldType::Map(Box::new(key_type), Box::new(value_type))
        } else {
            self.parse_type()?
        };
        let name = self.declaration_name()?;
        self.expect_symbol('=')?;
        let number = self.integer()?;
        let valid_range = i64::from(MIN_FIELD_NUMBER)..=i64::from(MAX_FIELD_NUMBER);
        let reserved_range =
            i64::from(RESERVED_FIELD_NUMBER_START)..=i64::from(RESERVED_FIELD_NUMBER_END);
        if !valid_range.contains(&number) || reserved_range.contains(&number) {
            return Err(Error::new(self.offset(), "invalid field number"));
        }
        let mut packed = None;
        let mut packed_explicit = false;
        let mut default = None;
        let mut options = Vec::new();
        if self.consume_symbol('[') {
            loop {
                if self.consume_symbol(']') {
                    break;
                }
                let option = self.option_setting()?;
                if option.name == OPTION_PACKED {
                    if packed.is_some() {
                        return Err(Error::new(self.offset(), "duplicate packed option"));
                    }
                    packed = match option.value.as_str() {
                        BOOLEAN_TRUE => Some(true),
                        BOOLEAN_FALSE => Some(false),
                        _ => {
                            return Err(Error::new(
                                self.offset(),
                                "packed option must be true or false",
                            ));
                        }
                    };
                    packed_explicit = true;
                } else if option.name == OPTION_DEFAULT {
                    if default.is_some() {
                        return Err(Error::new(self.offset(), "duplicate default option"));
                    }
                    default = Some(option.value.clone())
                }
                options.push(option);
                if !self.consume_symbol(']') {
                    self.expect_symbol(',')?;
                } else {
                    break;
                }
            }
        }
        self.expect_symbol(';')?;
        let cardinality = if matches!(kind, FieldType::Map(..)) {
            Cardinality::Repeated
        } else {
            declared_cardinality.unwrap_or(Cardinality::Optional)
        };
        if default.is_some()
            && (self.syntax == Syntax::Proto3
                || cardinality == Cardinality::Repeated
                || oneof.is_some()
                || matches!(kind, FieldType::Map(..)))
        {
            return Err(Error::new(
                self.offset(),
                "default option is not valid for this field",
            ));
        }
        if packed.is_some()
            && (cardinality != Cardinality::Repeated
                || matches!(
                    kind,
                    FieldType::String | FieldType::Bytes | FieldType::Map(..)
                ))
        {
            return Err(Error::new(
                self.offset(),
                "packed option requires a repeated primitive field",
            ));
        }
        let explicit_presence = declared_cardinality.is_some() || oneof.is_some();
        if packed.is_none()
            && cardinality == Cardinality::Repeated
            && !matches!(
                kind,
                FieldType::String | FieldType::Bytes | FieldType::Map(..)
            )
        {
            packed = Some(self.syntax.has_modern_defaults());
        }
        Ok(Field {
            name,
            number: number as u32,
            cardinality,
            kind,
            packed,
            packed_explicit,
            oneof,
            explicit_presence,
            default,
            options,
            features: FeatureSet::for_syntax(self.syntax),
        })
    }
    /// Parses a built-in scalar type or records a user-defined type for resolution.
    ///
    /// Unknown identifiers are intentionally stored as provisional message
    /// names; [`resolve_schema`] later distinguishes messages from enums using
    /// all declarations reachable through the registry.
    fn parse_type(&mut self) -> Result<FieldType> {
        let name = self.identifier()?;
        Ok(match name.as_str() {
            TYPE_DOUBLE => FieldType::Double,
            TYPE_FLOAT => FieldType::Float,
            TYPE_INT32 => FieldType::Int32,
            TYPE_INT64 => FieldType::Int64,
            TYPE_UINT32 => FieldType::Uint32,
            TYPE_UINT64 => FieldType::Uint64,
            TYPE_SINT32 => FieldType::Sint32,
            TYPE_SINT64 => FieldType::Sint64,
            TYPE_FIXED32 => FieldType::Fixed32,
            TYPE_FIXED64 => FieldType::Fixed64,
            TYPE_SFIXED32 => FieldType::Sfixed32,
            TYPE_SFIXED64 => FieldType::Sfixed64,
            TYPE_BOOL => FieldType::Bool,
            TYPE_STRING => FieldType::String,
            TYPE_BYTES => FieldType::Bytes,
            // User-defined names are resolved after every imported file has
            // been parsed, using protobuf's innermost-scope-first lookup.
            _ => FieldType::Message(name),
        })
    }
}

/// Rejects duplicate reserved names and overlapping numeric ranges.
fn validate_reserved_declarations(reserved: &ReservedDeclarations, offset: usize) -> Result<()> {
    for (index, name) in reserved.names.iter().enumerate() {
        if reserved
            .names
            .iter()
            .take(index)
            .any(|previous| previous == name)
        {
            return Err(Error::new(offset, "duplicate reserved name"));
        }
    }
    for (index, (start, end)) in reserved.ranges.iter().enumerate() {
        if reserved
            .ranges
            .iter()
            .take(index)
            .any(|(previous_start, previous_end)| start <= previous_end && previous_start <= end)
        {
            return Err(Error::new(offset, "overlapping reserved ranges"));
        }
    }
    Ok(())
}

/// Descriptor scope used to validate built-in and custom option placement.
#[derive(Clone, Copy)]
enum OptionTarget {
    File,
    Message,
    Field,
    Oneof,
    Enum,
    EnumValue,
    Service,
    Method,
}

/// Scalar category required by one built-in protobuf option.
#[derive(Clone, Copy)]
enum BuiltinOptionType {
    Bool,
    String,
    Identifier,
    AnyScalar,
    /// Scalar or aggregate value whose detailed shape belongs to a descriptor message.
    Any,
}

/// Returns the type of a built-in option valid at the supplied scope.
fn builtin_option_type(target: OptionTarget, name: &str) -> Option<BuiltinOptionType> {
    use BuiltinOptionType::{Any, AnyScalar, Bool, Identifier, String as StringOption};
    if matches!(
        name,
        FEATURE_FIELD_PRESENCE
            | FEATURE_ENUM_TYPE
            | FEATURE_REPEATED_ENCODING
            | FEATURE_MESSAGE_ENCODING
            | FEATURE_UTF8_VALIDATION
            | FEATURE_JSON_FORMAT
    ) {
        return Some(Identifier);
    }
    match target {
        OptionTarget::File => match name {
            "java_package"
            | "java_outer_classname"
            | "go_package"
            | "objc_class_prefix"
            | "csharp_namespace"
            | "swift_prefix"
            | "php_class_prefix"
            | "php_namespace"
            | "php_metadata_namespace"
            | "ruby_package" => Some(StringOption),
            "java_multiple_files"
            | "java_generate_equals_and_hash"
            | "java_string_check_utf8"
            | "cc_generic_services"
            | "java_generic_services"
            | "py_generic_services"
            | "php_generic_services"
            | "deprecated"
            | "cc_enable_arenas" => Some(Bool),
            "optimize_for" => Some(Identifier),
            _ => None,
        },
        OptionTarget::Message => match name {
            "message_set_wire_format"
            | "no_standard_descriptor_accessor"
            | "deprecated"
            | "map_entry"
            | "deprecated_legacy_json_field_conflicts" => Some(Bool),
            _ => None,
        },
        OptionTarget::Field => match name {
            OPTION_PACKED | "lazy" | "unverified_lazy" | "deprecated" | "weak" | "debug_redact" => {
                Some(Bool)
            }
            OPTION_DEFAULT => Some(AnyScalar),
            "json_name" => Some(StringOption),
            "ctype" | "jstype" | "retention" => Some(Identifier),
            "targets" => Some(Identifier),
            "edition_defaults" | "feature_support" => Some(Any),
            _ => None,
        },
        OptionTarget::Oneof => None,
        OptionTarget::Enum => match name {
            OPTION_ALLOW_ALIAS | "deprecated" | "deprecated_legacy_json_field_conflicts" => {
                Some(Bool)
            }
            _ => None,
        },
        OptionTarget::EnumValue => match name {
            "deprecated" | "debug_redact" => Some(Bool),
            "feature_support" => Some(Any),
            _ => None,
        },
        OptionTarget::Service => match name {
            "deprecated" => Some(Bool),
            _ => None,
        },
        OptionTarget::Method => match name {
            "deprecated" => Some(Bool),
            "idempotency_level" => Some(Identifier),
            _ => None,
        },
    }
}

/// Applies built-in Edition feature overrides to an inherited feature set.
fn apply_feature_options(
    inherited: FeatureSet,
    options: &[OptionSetting],
    target: OptionTarget,
    edition: bool,
) -> Result<FeatureSet> {
    let mut features = inherited;
    for option in options {
        let recognized = match option.name.as_str() {
            FEATURE_FIELD_PRESENCE => {
                if !matches!(
                    target,
                    OptionTarget::File | OptionTarget::Message | OptionTarget::Field
                ) {
                    return Err(Error::new(0, "field_presence feature is misplaced"));
                }
                features.field_presence = match option.value.as_str() {
                    "EXPLICIT" => FieldPresence::Explicit,
                    "IMPLICIT" => FieldPresence::Implicit,
                    "LEGACY_REQUIRED" => FieldPresence::LegacyRequired,
                    _ => return Err(Error::new(0, "invalid field_presence feature value")),
                };
                true
            }
            FEATURE_ENUM_TYPE => {
                if !matches!(target, OptionTarget::File | OptionTarget::Enum) {
                    return Err(Error::new(0, "enum_type feature is misplaced"));
                }
                features.enum_type = match option.value.as_str() {
                    "OPEN" => EnumType::Open,
                    "CLOSED" => EnumType::Closed,
                    _ => return Err(Error::new(0, "invalid enum_type feature value")),
                };
                true
            }
            FEATURE_REPEATED_ENCODING => {
                if !matches!(target, OptionTarget::File | OptionTarget::Field) {
                    return Err(Error::new(
                        0,
                        "repeated_field_encoding feature is misplaced",
                    ));
                }
                features.repeated_field_encoding = match option.value.as_str() {
                    "PACKED" => RepeatedFieldEncoding::Packed,
                    "EXPANDED" => RepeatedFieldEncoding::Expanded,
                    _ => {
                        return Err(Error::new(
                            0,
                            "invalid repeated_field_encoding feature value",
                        ));
                    }
                };
                true
            }
            FEATURE_MESSAGE_ENCODING => {
                if !matches!(target, OptionTarget::File | OptionTarget::Field) {
                    return Err(Error::new(0, "message_encoding feature is misplaced"));
                }
                features.message_encoding = match option.value.as_str() {
                    "LENGTH_PREFIXED" => MessageEncoding::LengthPrefixed,
                    "DELIMITED" => MessageEncoding::Delimited,
                    _ => return Err(Error::new(0, "invalid message_encoding feature value")),
                };
                true
            }
            FEATURE_UTF8_VALIDATION => {
                if !matches!(target, OptionTarget::File | OptionTarget::Field) {
                    return Err(Error::new(0, "utf8_validation feature is misplaced"));
                }
                features.utf8_validation = match option.value.as_str() {
                    "VERIFY" => Utf8Validation::Verify,
                    "NONE" => Utf8Validation::None,
                    _ => return Err(Error::new(0, "invalid utf8_validation feature value")),
                };
                true
            }
            FEATURE_JSON_FORMAT => {
                if !matches!(
                    target,
                    OptionTarget::File | OptionTarget::Message | OptionTarget::Enum
                ) {
                    return Err(Error::new(0, "json_format feature is misplaced"));
                }
                features.json_format = match option.value.as_str() {
                    "ALLOW" => JsonFormat::Allow,
                    "LEGACY_BEST_EFFORT" => JsonFormat::LegacyBestEffort,
                    _ => return Err(Error::new(0, "invalid json_format feature value")),
                };
                true
            }
            _ => false,
        };
        if recognized && !edition {
            return Err(Error::new(
                0,
                "features are available only in Editions sources",
            ));
        }
    }
    Ok(features)
}

/// Resolves file and lexical descriptor feature inheritance.
fn resolve_features(schema: &mut Schema) -> Result<()> {
    let edition = schema.syntax.is_edition();
    let root = apply_feature_options(
        FeatureSet::for_syntax(schema.syntax),
        &schema.options,
        OptionTarget::File,
        edition,
    )?;
    schema.features = root;
    let message_names: Vec<String> = schema.messages.keys().cloned().collect();
    let mut resolved_messages = BTreeMap::<String, FeatureSet>::new();
    for name in &message_names {
        let parent = message_names
            .iter()
            .filter(|candidate| {
                name.starts_with(candidate.as_str()) && name.as_str() != candidate.as_str()
            })
            .filter(|candidate| name.as_bytes().get(candidate.len()) == Some(&b'.'))
            .max_by_key(|candidate| candidate.len())
            .and_then(|candidate| resolved_messages.get(candidate))
            .copied()
            .unwrap_or(root);
        let descriptor = schema
            .messages
            .get_mut(name)
            .ok_or_else(|| Error::new(0, "message disappeared during feature resolution"))?;
        descriptor.features =
            apply_feature_options(parent, &descriptor.options, OptionTarget::Message, edition)?;
        for field in &mut descriptor.fields {
            field.features = apply_feature_options(
                descriptor.features,
                &field.options,
                OptionTarget::Field,
                edition,
            )?;
            if field.features.message_encoding == MessageEncoding::Delimited
                && !matches!(field.kind, FieldType::Message(_))
                && field
                    .options
                    .iter()
                    .any(|option| option.name == FEATURE_MESSAGE_ENCODING)
            {
                return Err(Error::new(
                    0,
                    format!(
                        "field {} applies DELIMITED encoding to a non-message",
                        field.name
                    ),
                ));
            }
            if field
                .options
                .iter()
                .any(|option| option.name == FEATURE_UTF8_VALIDATION)
                && !matches!(field.kind, FieldType::String)
            {
                return Err(Error::new(
                    0,
                    format!(
                        "field {} applies UTF-8 validation to a non-string",
                        field.name
                    ),
                ));
            }
            if field
                .options
                .iter()
                .any(|option| option.name == FEATURE_REPEATED_ENCODING)
                && field.cardinality != Cardinality::Repeated
            {
                return Err(Error::new(
                    0,
                    format!(
                        "field {} applies repeated encoding to a singular field",
                        field.name
                    ),
                ));
            }
            field.explicit_presence = field.explicit_presence
                || field.oneof.is_some()
                || matches!(field.kind, FieldType::Message(_))
                || field.features.field_presence != FieldPresence::Implicit;
            if field.default.is_some() && field.features.field_presence == FieldPresence::Implicit {
                return Err(Error::new(
                    0,
                    format!(
                        "field {} cannot combine implicit presence with a default",
                        field.name
                    ),
                ));
            }
            if field.cardinality == Cardinality::Repeated
                && !field.packed_explicit
                && !matches!(
                    field.kind,
                    FieldType::String
                        | FieldType::Bytes
                        | FieldType::Message(_)
                        | FieldType::Map(..)
                )
            {
                field.packed =
                    Some(field.features.repeated_field_encoding == RepeatedFieldEncoding::Packed);
            }
        }
        resolved_messages.insert(name.clone(), descriptor.features);
    }
    for enumeration in schema.enums.values_mut() {
        let parent = message_names
            .iter()
            .filter(|candidate| enumeration.full_name.starts_with(candidate.as_str()))
            .filter(|candidate| {
                enumeration.full_name.as_bytes().get(candidate.len()) == Some(&b'.')
            })
            .max_by_key(|candidate| candidate.len())
            .and_then(|candidate| resolved_messages.get(candidate))
            .copied()
            .unwrap_or(root);
        enumeration.features =
            apply_feature_options(parent, &enumeration.options, OptionTarget::Enum, edition)?;
    }
    for extension in schema.extensions.values_mut() {
        let scope = extension
            .full_name
            .rsplit_once('.')
            .map_or("", |(parent, _)| parent);
        let inherited = resolved_messages.get(scope).copied().unwrap_or(root);
        extension.field.features = apply_feature_options(
            inherited,
            &extension.field.options,
            OptionTarget::Field,
            edition,
        )?;
        extension.field.explicit_presence = extension.field.cardinality != Cardinality::Repeated
            && extension.field.features.field_presence != FieldPresence::Implicit;
        if extension.field.cardinality == Cardinality::Repeated
            && !extension.field.packed_explicit
            && !matches!(
                extension.field.kind,
                FieldType::String | FieldType::Bytes | FieldType::Message(_) | FieldType::Map(..)
            )
        {
            extension.field.packed = Some(
                extension.field.features.repeated_field_encoding == RepeatedFieldEncoding::Packed,
            );
        }
    }
    Ok(())
}

/// Validates built-in option names, scopes, scalar categories, and duplicates.
fn validate_options(options: &[OptionSetting], target: OptionTarget) -> Result<()> {
    for (index, option) in options.iter().enumerate() {
        if option.name.starts_with('(') {
            continue;
        }
        let expected = builtin_option_type(target, &option.name).ok_or_else(|| {
            Error::new(0, format!("unknown or misplaced option: {}", option.name))
        })?;
        if options[..index]
            .iter()
            .any(|previous| previous.name == option.name)
        {
            return Err(Error::new(0, format!("duplicate option: {}", option.name)));
        }
        let valid = match expected {
            BuiltinOptionType::Bool => {
                option.value_kind == OptionValueKind::Identifier
                    && matches!(option.value.as_str(), BOOLEAN_TRUE | BOOLEAN_FALSE)
            }
            BuiltinOptionType::String => option.value_kind == OptionValueKind::String,
            BuiltinOptionType::Identifier => option.value_kind == OptionValueKind::Identifier,
            BuiltinOptionType::AnyScalar => option.value_kind != OptionValueKind::Aggregate,
            BuiltinOptionType::Any => true,
        };
        if !valid {
            return Err(Error::new(
                0,
                format!("invalid value for option: {}", option.name),
            ));
        }
        if option.name == "optimize_for"
            && !matches!(
                option.value.as_str(),
                "SPEED" | "CODE_SIZE" | "LITE_RUNTIME"
            )
        {
            return Err(Error::new(0, "invalid optimize_for value"));
        }
        if option.name == "ctype"
            && !matches!(option.value.as_str(), "STRING" | "CORD" | "STRING_PIECE")
        {
            return Err(Error::new(0, "invalid ctype value"));
        }
        if option.name == "jstype"
            && !matches!(
                option.value.as_str(),
                "JS_NORMAL" | "JS_STRING" | "JS_NUMBER"
            )
        {
            return Err(Error::new(0, "invalid jstype value"));
        }
        if option.name == "idempotency_level"
            && !matches!(
                option.value.as_str(),
                "IDEMPOTENCY_UNKNOWN" | "NO_SIDE_EFFECTS" | "IDEMPOTENT"
            )
        {
            return Err(Error::new(0, "invalid idempotency_level value"));
        }
    }
    Ok(())
}

/// Returns whether a proto3 extension targets a descriptor option message.
fn is_custom_option_extendee(name: &str) -> bool {
    matches!(
        name,
        "google.protobuf.FileOptions"
            | "google.protobuf.MessageOptions"
            | "google.protobuf.FieldOptions"
            | "google.protobuf.OneofOptions"
            | "google.protobuf.EnumOptions"
            | "google.protobuf.EnumValueOptions"
            | "google.protobuf.ServiceOptions"
            | "google.protobuf.MethodOptions"
            | "google.protobuf.ExtensionRangeOptions"
    )
}

/// Returns the descriptor options message corresponding to one option scope.
fn option_target_extendee(target: OptionTarget) -> &'static str {
    match target {
        OptionTarget::File => "google.protobuf.FileOptions",
        OptionTarget::Message => "google.protobuf.MessageOptions",
        OptionTarget::Field => "google.protobuf.FieldOptions",
        OptionTarget::Oneof => "google.protobuf.OneofOptions",
        OptionTarget::Enum => "google.protobuf.EnumOptions",
        OptionTarget::EnumValue => "google.protobuf.EnumValueOptions",
        OptionTarget::Service => "google.protobuf.ServiceOptions",
        OptionTarget::Method => "google.protobuf.MethodOptions",
    }
}

/// Splits `(extension.name).field.path` into its extension and message path.
fn custom_option_parts(name: &str) -> Option<(&str, &str)> {
    let contents = name.strip_prefix('(')?;
    let closing = contents.find(')')?;
    let extension = &contents[..closing];
    let suffix = contents.get(closing + 1..)?;
    Some((extension, suffix.strip_prefix('.').unwrap_or(suffix)))
}

/// Resolves a custom-option extension with protobuf lexical name lookup.
fn resolve_custom_option<'a>(
    source_name: &str,
    scope: &str,
    options: &'a BTreeMap<String, CustomOptionDescriptor>,
) -> Option<&'a CustomOptionDescriptor> {
    let absolute = source_name.starts_with('.');
    let raw = source_name.trim_start_matches('.');
    if absolute {
        return options.get(raw);
    }
    let mut current = scope;
    loop {
        let candidate = if current.is_empty() {
            raw.to_string()
        } else {
            format!("{current}.{raw}")
        };
        if let Some(option) = options.get(&candidate) {
            return Some(option);
        }
        let Some((parent, _)) = current.rsplit_once('.') else {
            break;
        };
        current = parent;
    }
    options.get(raw)
}

/// Resolves a custom option's optional message-field suffix to its final type.
fn custom_option_value_type<'a>(
    descriptor: &'a CustomOptionDescriptor,
    path: &str,
    messages: &'a BTreeMap<String, MessageDescriptor>,
) -> Result<&'a FieldType> {
    let mut field_type = &descriptor.field.kind;
    if path.is_empty() {
        return Ok(field_type);
    }
    for component in path.split('.') {
        let FieldType::Message(message_name) = field_type else {
            return Err(Error::new(0, "custom option path traverses a scalar value"));
        };
        let message = messages.get(message_name).ok_or_else(|| {
            Error::new(0, format!("unknown custom option message: {message_name}"))
        })?;
        field_type = &message
            .field_by_name(component)
            .ok_or_else(|| Error::new(0, format!("unknown custom option field: {component}")))?
            .kind;
    }
    Ok(field_type)
}

/// Reports whether an option literal has the lexical category required by a field.
fn custom_option_value_is_valid(
    field_type: &FieldType,
    kind: OptionValueKind,
    value: &str,
) -> bool {
    match field_type {
        FieldType::Bool => {
            kind == OptionValueKind::Identifier && matches!(value, BOOLEAN_TRUE | BOOLEAN_FALSE)
        }
        FieldType::String | FieldType::Bytes => kind == OptionValueKind::String,
        FieldType::Enum(_) => matches!(kind, OptionValueKind::Identifier | OptionValueKind::Number),
        FieldType::Message(_) => kind == OptionValueKind::Aggregate,
        FieldType::Map(..) => false,
        _ => kind == OptionValueKind::Number,
    }
}

/// Validates custom-option lookup, placement, duplication, paths, and values.
fn validate_custom_options(
    settings: &[OptionSetting],
    target: OptionTarget,
    scope: &str,
    options: &BTreeMap<String, CustomOptionDescriptor>,
    messages: &BTreeMap<String, MessageDescriptor>,
) -> Result<()> {
    for (index, setting) in settings.iter().enumerate() {
        let Some((extension_name, path)) = custom_option_parts(&setting.name) else {
            continue;
        };
        let descriptor = resolve_custom_option(extension_name, scope, options)
            .ok_or_else(|| Error::new(0, format!("unknown custom option: {}", setting.name)))?;
        if descriptor.extendee != option_target_extendee(target) {
            return Err(Error::new(
                0,
                format!("custom option is not valid at this scope: {}", setting.name),
            ));
        }
        if descriptor.field.cardinality != Cardinality::Repeated
            && settings[..index]
                .iter()
                .any(|previous| previous.name == setting.name)
        {
            return Err(Error::new(
                0,
                format!("duplicate custom option: {}", setting.name),
            ));
        }
        let field_type = custom_option_value_type(descriptor, path, messages)?;
        if !custom_option_value_is_valid(field_type, setting.value_kind, &setting.value) {
            return Err(Error::new(
                0,
                format!("invalid value for custom option: {}", setting.name),
            ));
        }
    }
    Ok(())
}

/// Validates every retained option at its protobuf descriptor scope.
fn validate_schema_options(
    schema: &Schema,
    custom_options: &BTreeMap<String, CustomOptionDescriptor>,
    messages: &BTreeMap<String, MessageDescriptor>,
) -> Result<()> {
    let file_scope = schema.package.as_deref().unwrap_or("");
    validate_options(&schema.options, OptionTarget::File)?;
    validate_custom_options(
        &schema.options,
        OptionTarget::File,
        file_scope,
        custom_options,
        messages,
    )?;
    for message in schema.messages.values() {
        validate_options(&message.options, OptionTarget::Message)?;
        validate_custom_options(
            &message.options,
            OptionTarget::Message,
            &message.full_name,
            custom_options,
            messages,
        )?;
        for oneof in &message.oneofs {
            validate_options(&oneof.options, OptionTarget::Oneof)?;
            validate_custom_options(
                &oneof.options,
                OptionTarget::Oneof,
                &message.full_name,
                custom_options,
                messages,
            )?;
        }
        for field in &message.fields {
            validate_options(&field.options, OptionTarget::Field)?;
            validate_custom_options(
                &field.options,
                OptionTarget::Field,
                &message.full_name,
                custom_options,
                messages,
            )?;
        }
    }
    for enumeration in schema.enums.values() {
        validate_options(&enumeration.options, OptionTarget::Enum)?;
        validate_custom_options(
            &enumeration.options,
            OptionTarget::Enum,
            &enumeration.full_name,
            custom_options,
            messages,
        )?;
        for value in &enumeration.values {
            validate_options(&value.options, OptionTarget::EnumValue)?;
            validate_custom_options(
                &value.options,
                OptionTarget::EnumValue,
                &enumeration.full_name,
                custom_options,
                messages,
            )?;
        }
    }
    for service in schema.services.values() {
        validate_options(&service.options, OptionTarget::Service)?;
        validate_custom_options(
            &service.options,
            OptionTarget::Service,
            &service.full_name,
            custom_options,
            messages,
        )?;
        for method in &service.methods {
            validate_options(&method.options, OptionTarget::Method)?;
            validate_custom_options(
                &method.options,
                OptionTarget::Method,
                &service.full_name,
                custom_options,
                messages,
            )?;
        }
    }
    Ok(())
}

/// Derives the JSON spelling used by protobuf reflection for one field.
///
/// An explicit `json_name` takes precedence. Otherwise underscores are
/// removed and the following ASCII letter is capitalized, matching protoc's
/// lower-camel-case transformation for protobuf identifiers.
fn field_json_name(field: &Field) -> String {
    if let Some(option) = field
        .options
        .iter()
        .find(|option| option.name == "json_name")
    {
        return option.value.clone();
    }
    let mut name = String::new();
    let mut capitalize = false;
    for character in field.name.chars() {
        if character == '_' {
            capitalize = true;
        } else if capitalize {
            name.push(character.to_ascii_uppercase());
            capitalize = false;
        } else {
            name.push(character);
        }
    }
    name
}

/// Rejects proto3 fields that become ambiguous through their JSON names.
///
/// Binary tags remain distinct in this situation, but protobuf JSON parsers
/// could map one input property to multiple fields. Protoc rejects the schema,
/// so the dynamic descriptor builder applies the same semantic rule even
/// though this crate does not currently implement JSON serialization.
fn validate_json_field_names(fields: &[Field], offset: usize) -> Result<()> {
    for (index, field) in fields.iter().enumerate() {
        let json_name = field_json_name(field);
        if fields[..index]
            .iter()
            .any(|previous| field_json_name(previous) == json_name)
        {
            return Err(Error::new(
                offset,
                format!("duplicate proto3 JSON field name: {json_name}"),
            ));
        }
    }
    Ok(())
}

/// Validates field uniqueness, oneof names, and reserved declarations in a message.
fn validate_message_fields(
    fields: &[Field],
    oneof_names: &[String],
    reserved: &ReservedDeclarations,
    offset: usize,
) -> Result<()> {
    validate_reserved_declarations(reserved, offset)?;
    for (index, field) in fields.iter().enumerate() {
        if fields
            .iter()
            .take(index)
            .any(|previous| previous.name == field.name)
        {
            return Err(Error::new(offset, "duplicate field name"));
        }
        if fields
            .iter()
            .take(index)
            .any(|previous| previous.number == field.number)
        {
            return Err(Error::new(offset, "duplicate field number"));
        }
        if oneof_names.iter().any(|name| name == &field.name) {
            return Err(Error::new(offset, "field name conflicts with oneof name"));
        }
        if reserved.names.iter().any(|name| name == &field.name)
            || reserved
                .ranges
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&i64::from(field.number)))
        {
            return Err(Error::new(offset, "field uses a reserved name or number"));
        }
    }
    Ok(())
}

/// Parses one source file without resolving user-defined field types.
///
/// The resulting schema retains imports for later registry traversal.
fn parse_file(source: &str) -> Result<Schema> {
    validate_pest_syntax(source)?;
    let mut parser = DescriptorBuilder {
        tokens: lex(source)?,
        cursor: 0,
        syntax: Syntax::Proto2,
        package: None,
        messages: BTreeMap::new(),
        enums: BTreeMap::new(),
        services: BTreeMap::new(),
        custom_options: BTreeMap::new(),
        extensions: BTreeMap::new(),
        imports: Vec::new(),
        options: Vec::new(),
    };
    let mut seen_language = false;
    let mut seen_package = false;
    let mut seen_non_syntax = false;
    while parser.cursor < parser.tokens.len() {
        if parser.peek_identifier(KW_SYNTAX) || parser.peek_identifier(KW_EDITION) {
            if seen_language || seen_non_syntax {
                return Err(Error::new(
                    parser.offset(),
                    "syntax or edition declaration must occur once at the start of the file",
                ));
            }
            seen_language = true;
            let declaration = parser.identifier()?;
            parser.expect_symbol('=')?;
            let language_name = match parser.tokens.get(parser.cursor).cloned() {
                Some((Token::StringLiteral(value), _)) => {
                    parser.cursor += 1;
                    value
                }
                _ => {
                    return Err(Error::new(
                        parser.offset(),
                        "expected language version string",
                    ));
                }
            };
            parser.syntax = match (declaration.as_str(), language_name.as_str()) {
                (KW_SYNTAX, SYNTAX_PROTO2) => Syntax::Proto2,
                (KW_SYNTAX, SYNTAX_PROTO3) => Syntax::Proto3,
                (KW_EDITION, EDITION_2023) => Syntax::Edition2023,
                (KW_EDITION, _) => return Err(Error::new(parser.offset(), "unsupported edition")),
                _ => return Err(Error::new(parser.offset(), "unsupported syntax")),
            };
            parser.expect_symbol(';')?
        } else if parser.peek_identifier(KW_PACKAGE) {
            seen_non_syntax = true;
            if seen_package {
                return Err(Error::new(parser.offset(), "duplicate package declaration"));
            }
            seen_package = true;
            parser.identifier()?;
            parser.package = Some(parser.package_name()?);
            parser.expect_symbol(';')?
        } else if parser.peek_identifier(KW_IMPORT) {
            seen_non_syntax = true;
            parser.identifier()?;
            let kind = if parser.peek_identifier(KW_PUBLIC) {
                parser.identifier()?;
                ImportKind::Public
            } else if parser.peek_identifier(KW_WEAK) {
                parser.identifier()?;
                ImportKind::Weak
            } else {
                ImportKind::Normal
            };
            let path = match parser.tokens.get(parser.cursor).cloned() {
                Some((Token::StringLiteral(path), _)) => {
                    parser.cursor += 1;
                    path
                }
                _ => return Err(Error::new(parser.offset(), "expected import path string")),
            };
            parser.expect_symbol(';')?;
            parser.imports.push(Import { path, kind });
        } else if parser.peek_identifier(KW_MESSAGE) {
            seen_non_syntax = true;
            parser.parse_message("")?
        } else if parser.peek_identifier(KW_ENUM) {
            seen_non_syntax = true;
            parser.parse_enum("")?
        } else if parser.peek_identifier(KW_SERVICE) {
            seen_non_syntax = true;
            parser.parse_service()?
        } else if parser.peek_identifier(KW_OPTION) {
            seen_non_syntax = true;
            let option = parser.option_declaration()?;
            parser.options.push(option)
        } else if parser.peek_identifier(KW_EXTEND) {
            seen_non_syntax = true;
            parser.parse_custom_option_extensions("")?
        } else if parser.consume_symbol(';') {
            seen_non_syntax = true;
        } else {
            return Err(Error::new(
                parser.offset(),
                "unexpected top-level declaration",
            ));
        }
    }
    Ok(Schema {
        syntax: parser.syntax,
        package: parser.package,
        messages: parser.messages,
        enums: parser.enums,
        services: parser.services,
        custom_options: parser.custom_options,
        extensions: parser.extensions,
        imports: parser.imports,
        options: parser.options,
        features: FeatureSet::for_syntax(parser.syntax),
    })
}

/// Parses and resolves one self-contained schema.
///
/// Use [`Registry::parse`] when the source contains imports.
///
/// # Errors
///
/// Returns an error for invalid syntax, invalid field declarations, or
/// references to message and enum types absent from this source.
pub fn parse(source: &str) -> Result<Schema> {
    let mut schema = parse_file(source)?;
    resolve_schema(&mut schema)?;
    Ok(schema)
}

/// Traverses the registered import graph and combines its declarations.
///
/// A visited-path collection terminates cycles. Missing weak imports are
/// ignored, while missing normal/public imports and duplicate symbols fail.
/// The root source contributes the resulting schema's syntax and package.
fn parse_registry(root: &str, registry: &Registry) -> Result<Schema> {
    let mut pending = alloc::vec![root.to_string()];
    let mut files = BTreeMap::<String, Schema>::new();
    while let Some(path) = pending.pop() {
        if files.contains_key(&path) {
            continue;
        }
        let source = registry
            .source(&path)
            .ok_or_else(|| Error::new(0, format!("import not found: {path}")))?;
        let file = parse_file(source).map_err(|error| {
            Error::new(
                error.offset,
                format!("while parsing registry source {path}: {}", error.message),
            )
        })?;
        for import in &file.imports {
            if registry.source(&import.path).is_none() {
                if import.kind == ImportKind::Weak {
                    continue;
                }
                return Err(Error::new(0, format!("import not found: {}", import.path)));
            }
            pending.push(import.path.clone());
        }
        files.insert(path, file);
    }
    validate_import_cycles(root, &files, &mut BTreeMap::new())?;

    let paths: Vec<String> = files.keys().cloned().collect();
    let mut visibility = BTreeMap::<String, Vec<String>>::new();
    for path in &paths {
        visibility.insert(path.clone(), visible_import_paths(path, &files)?);
    }
    for path in &paths {
        let visible_paths = visibility
            .get(path)
            .ok_or_else(|| Error::new(0, "import visibility disappeared"))?;
        let mut visible_messages = BTreeMap::<String, MessageDescriptor>::new();
        let mut visible_enums = BTreeMap::<String, Syntax>::new();
        for visible_path in visible_paths {
            let visible = files
                .get(visible_path)
                .ok_or_else(|| Error::new(0, "visible source disappeared"))?;
            visible_messages.extend(visible.messages.clone());
            for (name, enumeration) in &visible.enums {
                visible_enums.insert(name.clone(), enumeration.syntax);
            }
        }
        let file = files
            .get_mut(path)
            .ok_or_else(|| Error::new(0, "registered source disappeared"))?;
        validate_symbol_namespaces(file)?;
        resolve_schema_declarations(file, &visible_messages, &visible_enums)?;
        resolve_features(file)?;
    }
    for path in &paths {
        let visible_paths = visibility
            .get(path)
            .ok_or_else(|| Error::new(0, "import visibility disappeared"))?;
        let mut visible_messages = BTreeMap::<String, MessageDescriptor>::new();
        let mut visible_custom_options = BTreeMap::<String, CustomOptionDescriptor>::new();
        for visible_path in visible_paths {
            let visible = files
                .get(visible_path)
                .ok_or_else(|| Error::new(0, "visible source disappeared"))?;
            visible_messages.extend(visible.messages.clone());
            visible_custom_options.extend(visible.custom_options.clone());
        }
        let file = files
            .get(path)
            .ok_or_else(|| Error::new(0, "registered source disappeared"))?;
        validate_schema_options(file, &visible_custom_options, &visible_messages)?;
    }

    let mut schema = files
        .remove(root)
        .ok_or_else(|| Error::new(0, "root schema not found"))?;
    for (_, file) in files {
        for (name, descriptor) in file.messages {
            if schema.messages.insert(name.clone(), descriptor).is_some() {
                return Err(Error::new(0, format!("duplicate message: {name}")));
            }
        }
        for (name, enumeration) in file.enums {
            if schema.enums.insert(name.clone(), enumeration).is_some() {
                return Err(Error::new(0, format!("duplicate enum: {name}")));
            }
        }
        for (name, service) in file.services {
            if schema.services.insert(name.clone(), service).is_some() {
                return Err(Error::new(0, format!("duplicate service: {name}")));
            }
        }
        for (name, option) in file.custom_options {
            if schema.custom_options.contains_key(&name)
                || schema.custom_options.values().any(|existing| {
                    existing.extendee == option.extendee
                        && existing.field.number == option.field.number
                })
            {
                return Err(Error::new(0, format!("duplicate custom option: {name}")));
            }
            schema.custom_options.insert(name, option);
        }
        for (name, extension) in file.extensions {
            if schema.extensions.contains_key(&name)
                || schema.extensions.values().any(|existing| {
                    existing.extendee == extension.extendee
                        && existing.field.number == extension.field.number
                })
            {
                return Err(Error::new(0, format!("duplicate extension: {name}")));
            }
            schema.extensions.insert(name, extension);
        }
        schema.imports.extend(file.imports);
    }
    validate_symbol_namespaces(&schema)?;
    Ok(schema)
}

/// Computes direct and publicly re-exported declarations visible to one file.
fn visible_import_paths(path: &str, files: &BTreeMap<String, Schema>) -> Result<Vec<String>> {
    let file = files
        .get(path)
        .ok_or_else(|| Error::new(0, "registered source disappeared"))?;
    let mut visible_paths = alloc::vec![path.to_string()];
    let mut public_frontier = Vec::<String>::new();
    for import in &file.imports {
        if files.contains_key(&import.path) && !visible_paths.contains(&import.path) {
            visible_paths.push(import.path.clone());
            public_frontier.push(import.path.clone());
        }
    }
    while let Some(imported_path) = public_frontier.pop() {
        let imported = files
            .get(&imported_path)
            .ok_or_else(|| Error::new(0, "visible import disappeared"))?;
        for public_import in imported
            .imports
            .iter()
            .filter(|import| import.kind == ImportKind::Public)
        {
            if files.contains_key(&public_import.path)
                && !visible_paths.contains(&public_import.path)
            {
                visible_paths.push(public_import.path.clone());
                public_frontier.push(public_import.path.clone());
            }
        }
    }
    Ok(visible_paths)
}

/// Rejects cycles in the reachable registry import graph.
fn validate_import_cycles(
    path: &str,
    files: &BTreeMap<String, Schema>,
    states: &mut BTreeMap<String, u8>,
) -> Result<()> {
    match states.get(path) {
        Some(1) => return Err(Error::new(0, format!("cyclic protobuf import: {path}"))),
        Some(2) => return Ok(()),
        _ => {}
    }
    states.insert(path.to_string(), 1);
    let file = files
        .get(path)
        .ok_or_else(|| Error::new(0, format!("import not found: {path}")))?;
    for import in &file.imports {
        if files.contains_key(&import.path) {
            validate_import_cycles(&import.path, files, states)?;
        }
    }
    states.insert(path.to_string(), 2);
    Ok(())
}

/// Resolves every deferred user-defined type and computes field presence rules.
///
/// Resolution runs after import merging so cross-file names are visible. It
/// also marks message fields as explicitly present and prevents non-packable
/// repeated strings, bytes, messages, and maps from using packed encoding.
fn resolve_schema(schema: &mut Schema) -> Result<()> {
    validate_symbol_namespaces(schema)?;
    let messages = schema.messages.clone();
    let enums: BTreeMap<String, Syntax> = schema
        .enums
        .iter()
        .map(|(name, enumeration)| (name.clone(), enumeration.syntax))
        .collect();
    resolve_schema_declarations(schema, &messages, &enums)?;
    resolve_features(schema)?;
    let resolved_messages = schema.messages.clone();
    let custom_options = schema.custom_options.clone();
    validate_schema_options(schema, &custom_options, &resolved_messages)
}

/// Resolves fields against the declarations visible from one source file.
fn resolve_schema_declarations(
    schema: &mut Schema,
    messages: &BTreeMap<String, MessageDescriptor>,
    enums: &BTreeMap<String, Syntax>,
) -> Result<()> {
    let message_names: Vec<String> = messages.keys().cloned().collect();
    let enum_names: Vec<String> = enums.keys().cloned().collect();
    for descriptor in schema.messages.values_mut() {
        for field in &mut descriptor.fields {
            resolve(
                &mut field.kind,
                &descriptor.full_name,
                &message_names,
                &enum_names,
            )?;
            if schema.syntax.has_modern_defaults() {
                reject_proto2_enum_reference(&field.kind, enums)?;
            }
            if field.packed_explicit
                && field.packed == Some(true)
                && matches!(
                    field.kind,
                    FieldType::String
                        | FieldType::Bytes
                        | FieldType::Message(_)
                        | FieldType::Map(..)
                )
            {
                return Err(Error::new(
                    0,
                    format!("field {} cannot use packed encoding", field.name),
                ));
            }
            if field.default.is_some()
                && matches!(field.kind, FieldType::Message(_) | FieldType::Map(..))
            {
                return Err(Error::new(
                    0,
                    format!("field {} cannot declare a default", field.name),
                ));
            }
            if matches!(field.kind, FieldType::Message(_)) {
                field.explicit_presence = true;
            }
            if field.cardinality == Cardinality::Repeated
                && matches!(
                    field.kind,
                    FieldType::String
                        | FieldType::Bytes
                        | FieldType::Message(_)
                        | FieldType::Map(..)
                )
            {
                field.packed = Some(false);
            }
        }
    }
    for option in schema.custom_options.values_mut() {
        if !messages.contains_key(&option.extendee) {
            return Err(Error::new(
                0,
                format!("custom option extendee is not visible: {}", option.extendee),
            ));
        }
        let scope = option
            .full_name
            .rsplit_once('.')
            .map_or("", |(parent, _)| parent);
        resolve(&mut option.field.kind, scope, &message_names, &enum_names)?;
        validate_options(&option.field.options, OptionTarget::Field)?;
    }
    for extension in schema.extensions.values_mut() {
        let mut extendee_type = FieldType::Message(extension.extendee.clone());
        let scope = extension
            .full_name
            .rsplit_once('.')
            .map_or("", |(parent, _)| parent);
        resolve(&mut extendee_type, scope, &message_names, &enum_names)?;
        let FieldType::Message(extendee) = extendee_type else {
            return Err(Error::new(0, "extension target must be a message"));
        };
        let target = messages
            .get(&extendee)
            .ok_or_else(|| Error::new(0, "extension target is not visible"))?;
        if !target
            .extension_ranges
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&extension.field.number))
        {
            return Err(Error::new(
                0,
                format!(
                    "extension {} is outside the target's extension ranges",
                    extension.full_name
                ),
            ));
        }
        if target.field_by_number(extension.field.number).is_some() {
            return Err(Error::new(
                0,
                "extension number collides with a regular field",
            ));
        }
        extension.extendee = extendee;
        resolve(
            &mut extension.field.kind,
            scope,
            &message_names,
            &enum_names,
        )?;
        validate_options(&extension.field.options, OptionTarget::Field)?;
    }
    let extensions: Vec<&ExtensionDescriptor> = schema.extensions.values().collect();
    for (index, extension) in extensions.iter().enumerate() {
        if extensions[..index].iter().any(|previous| {
            previous.extendee == extension.extendee
                && previous.field.number == extension.field.number
        }) {
            return Err(Error::new(
                0,
                format!(
                    "duplicate extension number {} for {}",
                    extension.field.number, extension.extendee
                ),
            ));
        }
    }
    for service in schema.services.values_mut() {
        for method in &mut service.methods {
            method.input_type = resolve_rpc_message(
                &method.input_type,
                &service.full_name,
                &message_names,
                &enum_names,
            )?;
            method.output_type = resolve_rpc_message(
                &method.output_type,
                &service.full_name,
                &message_names,
                &enum_names,
            )?;
        }
    }
    Ok(())
}

/// Rejects proto2 enum types referenced from a proto3 source file.
fn reject_proto2_enum_reference(
    field_type: &FieldType,
    enums: &BTreeMap<String, Syntax>,
) -> Result<()> {
    match field_type {
        FieldType::Enum(name) if enums.get(name) == Some(&Syntax::Proto2) => Err(Error::new(
            0,
            format!("proto3 field cannot reference proto2 enum: {name}"),
        )),
        FieldType::Map(key, value) => {
            reject_proto2_enum_reference(key, enums)?;
            reject_proto2_enum_reference(value, enums)
        }
        _ => Ok(()),
    }
}

/// Resolves an RPC endpoint and requires it to name a message declaration.
fn resolve_rpc_message(
    source_name: &str,
    scope: &str,
    messages: &[String],
    enums: &[String],
) -> Result<String> {
    let mut field_type = FieldType::Message(source_name.to_string());
    resolve(&mut field_type, scope, messages, enums)?;
    match field_type {
        FieldType::Message(name) => Ok(name),
        FieldType::Enum(name) => Err(Error::new(
            0,
            format!("rpc endpoint must be a message, not enum: {name}"),
        )),
        _ => Err(Error::new(0, "rpc endpoint must be a message")),
    }
}

/// Validates protobuf's shared declaration namespaces before type resolution.
fn validate_symbol_namespaces(schema: &Schema) -> Result<()> {
    let mut symbols = BTreeMap::<String, &'static str>::new();
    for name in schema.messages.keys() {
        if symbols.insert(name.clone(), "message").is_some() || schema.enums.contains_key(name) {
            return Err(Error::new(
                0,
                format!("conflicting declaration name: {name}"),
            ));
        }
    }
    for name in schema.enums.keys() {
        if symbols.insert(name.clone(), "enum").is_some() {
            return Err(Error::new(
                0,
                format!("conflicting declaration name: {name}"),
            ));
        }
    }
    for name in schema.services.keys() {
        if symbols.insert(name.clone(), "service").is_some() {
            return Err(Error::new(
                0,
                format!("conflicting declaration name: {name}"),
            ));
        }
    }
    for name in schema.custom_options.keys() {
        if symbols.insert(name.clone(), "custom option").is_some() {
            return Err(Error::new(
                0,
                format!("conflicting declaration name: {name}"),
            ));
        }
    }
    for descriptor in schema.messages.values() {
        for field in &descriptor.fields {
            let name = format!("{}.{}", descriptor.full_name, field.name);
            if symbols.insert(name.clone(), "field").is_some() {
                return Err(Error::new(
                    0,
                    format!("conflicting declaration name: {name}"),
                ));
            }
        }
        let mut oneofs = Vec::<&str>::new();
        for oneof in descriptor
            .fields
            .iter()
            .filter_map(|field| field.oneof.as_deref())
        {
            if oneofs.contains(&oneof) {
                continue;
            }
            oneofs.push(oneof);
            let name = format!("{}.{}", descriptor.full_name, oneof);
            if symbols.insert(name.clone(), "oneof").is_some() {
                return Err(Error::new(
                    0,
                    format!("conflicting declaration name: {name}"),
                ));
            }
        }
    }
    for enumeration in schema.enums.values() {
        let parent = enumeration
            .full_name
            .rsplit_once('.')
            .map_or("", |(parent, _)| parent);
        for value in &enumeration.values {
            let name = if parent.is_empty() {
                value.name.clone()
            } else {
                format!("{parent}.{}", value.name)
            };
            if symbols.insert(name.clone(), "enum value").is_some() {
                return Err(Error::new(
                    0,
                    format!("conflicting declaration name: {name}"),
                ));
            }
        }
    }
    Ok(())
}

/// Resolves one field type using protobuf's innermost-scope-first name lookup.
///
/// Absolute names bypass lexical scope. Relative names try the containing
/// message, each enclosing scope, and finally the unqualified global name.
/// Map key and value types are resolved recursively.
fn resolve(t: &mut FieldType, scope: &str, messages: &[String], enums: &[String]) -> Result<()> {
    match t {
        FieldType::Message(n) => {
            let absolute = n.starts_with('.');
            let raw = n.trim_start_matches('.');
            let mut candidates = Vec::new();
            if absolute {
                candidates.push(raw.to_string());
            } else {
                let mut current = scope;
                loop {
                    candidates.push(format!("{current}.{raw}"));
                    if let Some(index) = current.rfind('.') {
                        current = &current[..index];
                    } else {
                        break;
                    }
                }
                candidates.push(raw.to_string());
            }
            if let Some(name) = candidates.iter().find(|x| messages.contains(x)) {
                *n = name.clone();
            } else if let Some(name) = candidates.iter().find(|x| enums.contains(x)) {
                *t = FieldType::Enum(name.clone());
            } else {
                return Err(Error::new(0, format!("unknown type {n} in {scope}")));
            }
        }
        FieldType::Map(a, b) => {
            resolve(a, scope, messages, enums)?;
            resolve(b, scope, messages, enums)?;
        }
        _ => {}
    }
    Ok(())
}
