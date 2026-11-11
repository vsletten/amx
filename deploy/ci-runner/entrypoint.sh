#!/usr/bin/env bash
# Start a private Docker daemon, register the runner on first start, then run it.
set -euo pipefail

# cgroup v2 nesting, as moby's hack/dind does: move this container's processes
# into a child group so the inner daemon can delegate controllers.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  mkdir -p /sys/fs/cgroup/init
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || :
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
    > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || :
fi

dockerd --host=unix:///var/run/docker.sock > /var/log/dockerd.log 2>&1 &
for _ in $(seq 60); do
  docker info > /dev/null 2>&1 && break
  sleep 1
done
docker info > /dev/null || { tail -50 /var/log/dockerd.log; exit 1; }

cd /opt/actions-runner
if [ ! -f .runner ]; then
  : "${RUNNER_URL:?}" "${RUNNER_NAME:?}" "${RUNNER_LABELS:?}"
  : "${RUNNER_TOKEN:?first start needs a registration token}"
  sudo -u runner ./config.sh --unattended --replace \
    --url "$RUNNER_URL" --token "$RUNNER_TOKEN" \
    --name "$RUNNER_NAME" --labels "$RUNNER_LABELS" --work _work
fi
unset RUNNER_TOKEN
exec sudo -u runner ./run.sh
