#!/usr/bin/env bash
set -euo pipefail

MODE="$1"
case "$MODE" in
  juice-shop)
    export HOST=0.0.0.0
    export PORT=3000
    cd /opt/juice-shop
    exec /opt/node22/bin/npm start
    ;;
  nodegoat)
    export MONGODB_URI=mongodb://127.0.0.1:27017/nodegoat
    export PORT=4000
    mkdir -p /data/db
    mongod --bind_ip 127.0.0.1 --dbpath /data/db --quiet &
    mongo_pid=$!
    app_pid=0
    cleanup() {
      if [ "$app_pid" -gt 0 ]; then kill "$app_pid" 2>/dev/null || true; fi
      kill "$mongo_pid" 2>/dev/null || true
      wait "$mongo_pid" 2>/dev/null || true
    }
    trap cleanup EXIT INT TERM
    ready=0
    for attempt in $(seq 1 60); do
      if mongo --quiet --host 127.0.0.1 --eval 'db.adminCommand({ ping: 1 }).ok' >/dev/null 2>&1; then
        ready=1
        break
      fi
      sleep 1
    done
    if [ "$ready" -ne 1 ]; then echo "MongoDB did not become ready." >&2; exit 1; fi
    cd /opt/nodegoat
    export PATH="/opt/node12/bin:$PATH"
    npm run db:seed
    npm start &
    app_pid=$!
    wait "$app_pid"
    ;;
  *)
    echo "Unknown lab mode. Allowed values: juice-shop, nodegoat." >&2
    exit 64
    ;;
esac
