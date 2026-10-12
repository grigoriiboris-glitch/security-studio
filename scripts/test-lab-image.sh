#!/usr/bin/env bash
set -euo pipefail

IMAGE="$1"
NETWORK="security-studio-ci-no-egress"
CONTAINER="security-studio-ci-lab"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create --opt com.docker.network.bridge.enable_ip_masquerade=false "$NETWORK" >/dev/null

if [ "$(docker network inspect -f '{{index .Options "com.docker.network.bridge.enable_ip_masquerade"}}' "$NETWORK")" != "false" ]; then
  echo "FAIL: lab network unexpectedly enables outbound NAT" >&2
  exit 1
fi

assert_no_egress() {
  if docker exec "$CONTAINER" node -e 'const c=new AbortController();const t=setTimeout(()=>c.abort(),4000);fetch("https://example.com",{signal:c.signal}).then(()=>{console.error("Unexpected outbound network access");process.exitCode=1},()=>{process.exitCode=0}).finally(()=>clearTimeout(t))'; then
    echo "PASS: $1 cannot reach the public internet"
  else
    echo "FAIL: $1 has outbound network access" >&2
    return 1
  fi
}

assert_juice_shop_sqli() {
  local payload response
  payload='{"email":"'"'"' OR 1=1--","password":"security-studio-invalid-password"}'
  response=$(curl --silent --show-error --max-time 8 \
    -X POST "http://127.0.0.1:13000/rest/user/login" \
    -H "Content-Type: application/json" --data "$payload")
  if printf '%s' "$response" | python3 -c 'import json,sys; token=json.load(sys.stdin).get("authentication",{}).get("token"); sys.exit(0 if isinstance(token,str) and token else 1)'; then
    echo "PASS: known SQLi payload produced a session in the intentionally vulnerable Juice Shop"
  else
    echo "FAIL: expected SQLi behavior was not observed in Juice Shop" >&2
    return 1
  fi
}

run_lab() {
  local mode="$1" host_port="$2" container_port="$3" path="$4"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --init \
    --name "$CONTAINER" \
    --label security-studio.managed=true \
    --label "security-studio.lab=$mode" \
    --network "$NETWORK" \
    -p "127.0.0.1:$host_port:$container_port" \
    --memory=2g --cpus=2 --pids-limit=512 \
    --security-opt=no-new-privileges:true --cap-drop=ALL --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=128m,uid=999,gid=999 \
    --tmpfs /data/db:rw,nosuid,nodev,size=256m,uid=999,gid=999 \
    --tmpfs /opt/juice-shop/data:rw,nosuid,nodev,size=256m,uid=999,gid=999 \
    --tmpfs /opt/juice-shop/i18n:rw,nosuid,nodev,size=16m,uid=999,gid=999 \
    --tmpfs /opt/juice-shop/.well-known:rw,nosuid,nodev,size=8m,uid=999,gid=999 \
    --tmpfs /opt/juice-shop/frontend/dist/frontend:rw,nosuid,nodev,size=128m,uid=999,gid=999 \
    --tmpfs /opt/juice-shop/ftp:rw,nosuid,nodev,size=16m,uid=999,gid=999 \
    --tmpfs /opt/juice-shop/logs:rw,nosuid,nodev,size=32m,uid=999,gid=999 \
    "$IMAGE" "$mode" >/dev/null
  for attempt in $(seq 1 600); do
    if curl --silent --show-error --fail "http://127.0.0.1:$host_port$path" >/dev/null 2>&1; then
      echo "PASS: $mode answered HTTP on port $host_port"
      if [ "$mode" = "juice-shop" ]; then assert_juice_shop_sqli; fi
      assert_no_egress "$mode"
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
