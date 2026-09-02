#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_dir/deploy/docker-compose.yml"
export HPK_TURN_SHARED_SECRET="${HPK_TURN_SHARED_SECRET:-$(openssl rand -hex 32)}"

cleanup() {
  docker compose -f "$compose_file" down --volumes
}
trap cleanup EXIT

docker compose -f "$compose_file" up --build --detach --wait
curl --fail --silent http://127.0.0.1:8080/healthz
curl --fail --silent http://127.0.0.1:8080/v1/config
