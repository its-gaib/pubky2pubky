#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

assert_rejected() {
  local setting="$1"
  if env "$setting=untrusted" bash "$repo_dir/scripts/build-browser.sh" >/dev/null 2>&1; then
    echo "browser build accepted forbidden environment setting $setting" >&2
    exit 1
  fi
}

assert_rejected 'CC_wasm32-unknown-unknown'
assert_rejected CFLAGS
assert_rejected RUSTC_WRAPPER
assert_rejected CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS
