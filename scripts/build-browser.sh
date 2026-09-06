#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$repo_dir/packages/browser/generated"
llvm_root="/home/gaib/.local/llvm-21/root/usr"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.91.0}"

if [[ -x "$llvm_root/bin/clang-21" ]]; then
  export CC_wasm32_unknown_unknown="$llvm_root/bin/clang-21"
  export LD_LIBRARY_PATH="$llvm_root/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
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

(
  cd "$output_dir"
  find . -type f ! -name artifact.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    > artifact.sha256
)
