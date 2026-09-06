#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
output_dir="$repo_dir/packages/browser/generated"
cargo_home="${CARGO_HOME:-${HOME:?}/.cargo}"
cargo_home="$(cd "$cargo_home" && pwd -P)"
tool_root="${PUBKY2PUBKY_TOOL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/pubky2pubky-tools}"
wasi_root="$tool_root/wasi-sdk-34.0"
binaryen_root="$tool_root/binaryen-version_117"

blocked_environment=(
  RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
  CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
  CARGO_BUILD_RUSTFLAGS CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS
  CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER
  CC CFLAGS CPPFLAGS CXX CXXFLAGS AR ARFLAGS TARGET_CC TARGET_CFLAGS TARGET_CXX
  TARGET_CXXFLAGS TARGET_AR TARGET_ARFLAGS CRATE_CC_NO_DEFAULTS CC_FORCE_DISABLE
  CC_KNOWN_WRAPPER_CUSTOM CC_SHELL_ESCAPED_FLAGS
  CC_wasm32_unknown_unknown CFLAGS_wasm32_unknown_unknown
  CXX_wasm32_unknown_unknown CXXFLAGS_wasm32_unknown_unknown
  AR_wasm32_unknown_unknown ARFLAGS_wasm32_unknown_unknown
  'CC_wasm32-unknown-unknown' 'CFLAGS_wasm32-unknown-unknown'
  'CXX_wasm32-unknown-unknown' 'CXXFLAGS_wasm32-unknown-unknown'
  'AR_wasm32-unknown-unknown' 'ARFLAGS_wasm32-unknown-unknown'
)
for variable in "${blocked_environment[@]}"; do
  if printenv "$variable" >/dev/null 2>&1; then
    echo "refusing caller build setting $variable for the reproducible browser build" >&2
    exit 1
  fi
done
mapfile -t environment_names < <(compgen -e)
for variable in "${environment_names[@]}"; do
  if [[ "$variable" == CARGO_PROFILE_RELEASE_* ]]; then
    echo "refusing caller build setting $variable for the reproducible browser build" >&2
    exit 1
  fi
done
if [[ -n "${RUSTUP_TOOLCHAIN:-}" && "$RUSTUP_TOOLCHAIN" != "1.91.0" ]]; then
  echo "the browser build requires Rust 1.91.0" >&2
  exit 1
fi

export RUSTUP_TOOLCHAIN="1.91.0"
export TMPDIR="$repo_dir/target/tmp"
mkdir -p "$TMPDIR"

# Keep source locations stable across local and CI builds. Rust embeds panic locations in the
# release Wasm, while ring's C build can retain source paths in compiler metadata.
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$repo_dir=/workspace/pubky2pubky"$'\x1f'"--remap-path-prefix=$cargo_home=/cargo"
export CFLAGS_wasm32_unknown_unknown="-ffile-prefix-map=$repo_dir=/workspace/pubky2pubky -ffile-prefix-map=$cargo_home=/cargo"
export CC_wasm32_unknown_unknown="$wasi_root/bin/clang-23"
export AR_wasm32_unknown_unknown="$wasi_root/bin/llvm-ar"
export PATH="$binaryen_root/bin:$PATH"

if ! printf '%s  %s\n' "061f88b9f4c48f3742434c2513d5038ab7fa4dc27abff5cb13b5eaedcb51d6ea" "$CC_wasm32_unknown_unknown" | sha256sum --check --status \
  || ! printf '%s  %s\n' "aff24388a6589b45837cff1b50c7efaa203efa0e5f1e5f679b70b2d8feded9cf" "$AR_wasm32_unknown_unknown" | sha256sum --check --status \
  || ! printf '%s  %s\n' "621b5a984f16d0323ea7aa8b389ac9ccda0950ddee5de0e99292970129f571ed" "$binaryen_root/bin/wasm-opt" | sha256sum --check --status; then
  echo "browser toolchain missing or invalid; run npm run setup:browser-toolchain" >&2
  exit 1
fi
if [[ "$(rustc --version)" != "rustc 1.91.0 (f8297e351 2025-10-28)" \
  || "$(wasm-pack --version)" != "wasm-pack 0.15.0" \
  || "$(wasm-bindgen --version)" != "wasm-bindgen 0.2.127" \
  || "$(wasm-opt --version)" != "wasm-opt version 117 (version_117)" ]]; then
  echo "browser build tool version mismatch" >&2
  exit 1
fi

rm -rf "$output_dir"
wasm-pack build "$repo_dir/crates/browser-wasm" \
  --target web \
  --release \
  --out-dir "$output_dir" \
  --out-name pubky2pubky_browser_wasm

# wasm-pack assumes generated packages are normally ignored. This repository intentionally
# commits the immutable artifact so downstream vibes can pin an audited Git commit.
if [[ -f "$output_dir/.gitignore" ]]; then
  rm "$output_dir/.gitignore"
fi

wasm_file="$output_dir/pubky2pubky_browser_wasm_bg.wasm"
if LC_ALL=C grep -aFq "$repo_dir" "$wasm_file" || LC_ALL=C grep -aFq "$cargo_home" "$wasm_file"; then
  echo "generated Wasm contains a host-specific source path" >&2
  exit 1
fi

manifest_tmp="$(mktemp "$output_dir/.artifact.sha256.XXXXXX")"
trap 'rm -f "$manifest_tmp"' EXIT
(
  cd "$output_dir"
  find . -type f ! -name artifact.sha256 ! -name '.artifact.sha256.*' -print0 \
    | sort -z \
    | xargs -0 sha256sum
) > "$manifest_tmp"
mv "$manifest_tmp" "$output_dir/artifact.sha256"
trap - EXIT
