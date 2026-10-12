#!/usr/bin/env bash
set -euo pipefail

IMAGE="$1"
NETWORK="security-studio-ci-internal"
CONTAINER="security-studio-ci-lab"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create --internal "$NETWORK" >/dev/null

run_lab() {
  local mode="$1" host_port="$2" container_port="$3" path="$4"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --init \
    --name "$CONTAINER" \
    --label security-studio.managed=true \
    --label "security-studio.lab=$mode" \
    --network "$NETWORK" \
    -p "127.0.0.1:$host_port:$container_port" \
    --memory=1g --cpus=1 --pids-limit=256 \
    --security-opt=no-new-privileges:true --cap-drop=ALL --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=128m,uid=999,gid=999 \
    --tmpfs /data/db:rw,nosuid,nodev,size=256m,uid=999,gid=999 \
    --tmpfs /opt/juice-shop/data:rw,nosuid,nodev,size=256m,uid=999,gid=999 \
    --tmpfs /opt/juice-shop/logs:rw,nosuid,nodev,size=32m,uid=999,gid=999 \
    "$IMAGE" "$mode" >/dev/null
  for attempt in $(seq 1 90); do
    if curl --silent --show-error --fail "http://127.0.0.1:$host_port$path" >/dev/null 2>&1; then
      echo "PASS: $mode answered HTTP on port $host_port"
      docker rm -f "$CONTAINER" >/dev/null
      return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" != "true" ]; then
      docker logs "$CONTAINER" || true
      echo "FAIL: $mode exited before becoming ready" >&2
      return 1
    fi
    sleep 2
  done
  docker logs "$CONTAINER" || true
  echo "FAIL: $mode did not answer HTTP in time" >&2
  return 1
}
run_lab "juice-shop" 13000 3000 /
run_lab "nodegoat" 14000 4000 /tutorial
