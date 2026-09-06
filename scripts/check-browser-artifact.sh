#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
generated_dir="$repo_dir/packages/browser/generated"

test -f "$generated_dir/artifact.sha256"
mapfile -t storage_snippets < <(find "$generated_dir/snippets" -type f -path '*/js/browser_store.js')
if [[ "${#storage_snippets[@]}" -ne 1 ]]; then
  echo "expected exactly one generated browser_store.js snippet" >&2
  exit 1
fi
cmp "$repo_dir/crates/browser-wasm/js/browser_store.js" "${storage_snippets[0]}"
(
  cd "$generated_dir"
  sha256sum --check artifact.sha256
)
