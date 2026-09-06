#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
export TMPDIR="$repo_dir/target/tmp"
mkdir -p "$TMPDIR"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo audit
npm ci --ignore-scripts
npm run setup:browser-toolchain
bash scripts/test-build-environment.sh
npm run build:browser
npm run check:browser-artifact
npm run test:browser
shellcheck scripts/*.sh
