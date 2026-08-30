#!/usr/bin/env bash
set -euo pipefail

# Build and run Google's official conformance test suite against the codec.
# Host-only tools are isolated here; the Rust library remains no_std + alloc.
# CI may provide an exact-version runner through CONFORMANCE_RUNNER and its
# matching source tree through PROTOBUF_SOURCE_ROOT. Without those variables,
# this script builds the checked-in runner sources against host dependencies.
script_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
upstream_dir="$script_dir/upstream"
source_root="${PROTOBUF_SOURCE_ROOT:-$upstream_dir}"
build_dir="$project_dir/target/conformance"
generated_dir="$build_dir/generated"
runner="${CONFORMANCE_RUNNER:-$build_dir/conformance_test_runner}"

command -v cargo >/dev/null || {
  echo "missing required host tool: cargo" >&2
  exit 2
}

if [[ -n "${CONFORMANCE_RUNNER:-}" ]]; then
  [[ -x "$runner" ]] || {
    echo "CONFORMANCE_RUNNER is not an executable file: $runner" >&2
    exit 2
  }
  [[ -d "$source_root/src" && -d "$source_root/conformance" ]] || {
    echo "PROTOBUF_SOURCE_ROOT is not a protobuf source tree: $source_root" >&2
    exit 2
  }
else
  for tool in protoc c++ pkg-config; do
    command -v "$tool" >/dev/null || {
      echo "missing required host tool: $tool" >&2
      exit 2
    }
  done
  pkg-config --exists protobuf jsoncpp || {
    echo "pkg-config packages protobuf and jsoncpp are required" >&2
    exit 2
  }

  mkdir -p "$generated_dir"

  # Generated C++ descriptors are build products and are intentionally not
  # vendored. They are regenerated from the pinned proto definitions.
  protoc \
    -I"$source_root" \
    -I"$source_root/src" \
    --cpp_out="$generated_dir" \
    "$source_root/conformance/conformance.proto" \
    "$source_root/conformance/test_protos/test_messages_edition2023.proto" \
    "$source_root/conformance/test_protos/test_messages_edition_unstable.proto" \
    "$source_root/editions/golden/test_messages_proto2_editions.proto" \
    "$source_root/editions/golden/test_messages_proto3_editions.proto" \
    "$source_root/src/google/protobuf/test_messages_proto2.proto" \
    "$source_root/src/google/protobuf/test_messages_proto3.proto"

  # A single compiler invocation avoids importing upstream's full CMake
  # project, generators, language backends, tests, and unrelated sources.
  c++ -std=c++17 -O0 \
    -I"$source_root" \
    -I"$source_root/conformance" \
    -I"$generated_dir" \
    -I"$generated_dir/src" \
    $(pkg-config --cflags protobuf jsoncpp) \
    "$source_root/conformance/binary_json_conformance_suite.cc" \
    "$source_root/conformance/binary_wireformat.cc" \
    "$source_root/conformance/conformance_test.cc" \
    "$source_root/conformance/conformance_test_main.cc" \
    "$source_root/conformance/conformance_test_runner.cc" \
    "$source_root/conformance/failure_list_trie_node.cc" \
    "$source_root/conformance/fork_pipe_runner.cc" \
    "$source_root/conformance/text_format_conformance_suite.cc" \
    "$generated_dir/conformance/conformance.pb.cc" \
    "$generated_dir/conformance/test_protos/test_messages_edition2023.pb.cc" \
    "$generated_dir/conformance/test_protos/test_messages_edition_unstable.pb.cc" \
    "$generated_dir/editions/golden/test_messages_proto2_editions.pb.cc" \
    "$generated_dir/editions/golden/test_messages_proto3_editions.pb.cc" \
    "$generated_dir/src/google/protobuf/test_messages_proto2.pb.cc" \
    "$generated_dir/src/google/protobuf/test_messages_proto3.pb.cc" \
    $(pkg-config --libs protobuf jsoncpp) \
    -o "$runner"
fi

cd "$project_dir"
cargo build --example conformance_testee
"$runner" \
  --enforce_recommended \
  "target/debug/examples/conformance_testee" \
  "$source_root"
