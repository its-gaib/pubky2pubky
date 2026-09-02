#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo audit

if [[ "${HPK_TEST_TURN:-0}" == "1" ]]; then
  : "${HPK_TEST_TURN_URL:?set HPK_TEST_TURN_URL}"
  : "${HPK_TEST_TURN_SECRET:?set HPK_TEST_TURN_SECRET}"
  cargo test -p hole-punchky-client forced_turn_path_relays_data_channel -- --ignored --nocapture
fi
