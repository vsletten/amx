#!/usr/bin/env bash
# Build the runner image and start N runners (default 3) on this host.
# Needs `gh` authenticated as a repo admin. Safe to rerun: running runners are left alone.
set -euo pipefail

count="${1:-3}"
repo="${AMX_CI_REPO:?Set AMX_CI_REPO to owner/repo}"
labels="${AMX_CI_LABELS:-amx-ci}"
image="amx-ci-runner:local"
here="$(cd "$(dirname "$0")" && pwd)"

docker build -t "$image" "$here"

for n in $(seq 1 "$count"); do
  name="amx-ci-runner-$n"
  if docker ps --format '{{.Names}}' | grep -qx "$name"; then
    echo "$name already running"
    continue
  fi
  docker rm -f "$name" > /dev/null 2>&1 || true
  token="$(gh api -X POST "repos/$repo/actions/runners/registration-token" -q .token)"
  docker run -d --name "$name" --hostname "$name" --privileged --restart unless-stopped \
    -v "$name-docker:/var/lib/docker" \
    -e RUNNER_URL="https://github.com/$repo" \
    -e RUNNER_NAME="$(hostname -s)-$name" \
    -e RUNNER_LABELS="$labels" \
    -e RUNNER_TOKEN="$token" \
    "$image" > /dev/null
  echo "$name started"
done
