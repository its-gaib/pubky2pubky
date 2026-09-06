#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "the reproducible browser toolchain currently supports Linux x86_64 only" >&2
  exit 1
fi

tool_root="${PUBKY2PUBKY_TOOL_CACHE:-${XDG_CACHE_HOME:-${HOME:?}/.cache}/pubky2pubky-tools}"
if [[ -z "$tool_root" || "$tool_root" == "/" ]]; then
  echo "refusing unsafe browser toolchain cache path" >&2
  exit 1
fi

downloads="$tool_root/downloads"
wasi_root="$tool_root/wasi-sdk-34.0"
binaryen_root="$tool_root/binaryen-version_117"
mkdir -p "$downloads"

download_tmp=""
extract_tmp=""
cleanup() {
  [[ -z "$download_tmp" ]] || rm -f -- "$download_tmp"
  [[ -z "$extract_tmp" ]] || rm -rf -- "$extract_tmp"
}
trap cleanup EXIT

download_verified() {
  local url="$1"
  local expected_sha="$2"
  local archive="$3"

  if [[ -f "$archive" ]] && printf '%s  %s\n' "$expected_sha" "$archive" | sha256sum --check --status; then
    return
  fi

  download_tmp="$(mktemp "$downloads/.download.XXXXXX")"
  curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
    --output "$download_tmp" "$url"
  printf '%s  %s\n' "$expected_sha" "$download_tmp" | sha256sum --check --status
  mv "$download_tmp" "$archive"
  download_tmp=""
}

wasi_archive="$downloads/wasi-sdk-34.0-x86_64-linux.tar.gz"
wasi_archive_sha="b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4"
wasi_clang_sha="061f88b9f4c48f3742434c2513d5038ab7fa4dc27abff5cb13b5eaedcb51d6ea"
wasi_ar_sha="aff24388a6589b45837cff1b50c7efaa203efa0e5f1e5f679b70b2d8feded9cf"

if ! printf '%s  %s\n' "$wasi_clang_sha" "$wasi_root/bin/clang-23" | sha256sum --check --status \
  || ! printf '%s  %s\n' "$wasi_ar_sha" "$wasi_root/bin/llvm-ar" | sha256sum --check --status; then
  download_verified \
    "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz" \
    "$wasi_archive_sha" \
    "$wasi_archive"
  extract_tmp="$(mktemp -d "$tool_root/.wasi-sdk-34.0.XXXXXX")"
  tar -xzf "$wasi_archive" --strip-components=1 -C "$extract_tmp"
  printf '%s  %s\n' "$wasi_clang_sha" "$extract_tmp/bin/clang-23" | sha256sum --check --status
  printf '%s  %s\n' "$wasi_ar_sha" "$extract_tmp/bin/llvm-ar" | sha256sum --check --status
  rm -rf -- "$wasi_root"
  mv "$extract_tmp" "$wasi_root"
  extract_tmp=""
fi

binaryen_archive="$downloads/binaryen-version_117-x86_64-linux.tar.gz"
binaryen_archive_sha="3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212"
wasm_opt_sha="621b5a984f16d0323ea7aa8b389ac9ccda0950ddee5de0e99292970129f571ed"

if ! printf '%s  %s\n' "$wasm_opt_sha" "$binaryen_root/bin/wasm-opt" | sha256sum --check --status; then
  download_verified \
    "https://github.com/WebAssembly/binaryen/releases/download/version_117/binaryen-version_117-x86_64-linux.tar.gz" \
    "$binaryen_archive_sha" \
    "$binaryen_archive"
  extract_tmp="$(mktemp -d "$tool_root/.binaryen-version_117.XXXXXX")"
  tar -xzf "$binaryen_archive" --strip-components=1 -C "$extract_tmp"
  printf '%s  %s\n' "$wasm_opt_sha" "$extract_tmp/bin/wasm-opt" | sha256sum --check --status
  rm -rf -- "$binaryen_root"
  mv "$extract_tmp" "$binaryen_root"
  extract_tmp=""
fi

printf 'browser toolchain ready at %s\n' "$tool_root"
