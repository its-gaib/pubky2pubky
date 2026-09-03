#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo audit
npm ci --ignore-scripts
npm run lint:schemas
shellcheck scripts/*.sh

if [[ "${HPK_TEST_CONTAINERS:-0}" == "1" ]]; then
  "$repo_dir/scripts/container-smoke.sh"
fi
