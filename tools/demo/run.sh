#!/bin/sh
# Rebuilds the screenshots in docs/screenshots from demo data (example.com, nothing real).
#
# Needs Docker, openssl and python3. Builds the server for this machine, runs it on a fresh demo
# configuration with the schedule off, captures the pages with Playwright's headless Chromium, and
# stops the server again.
set -eu
cd "$(dirname "$0")/../.."
PLAYWRIGHT_IMAGE=mcr.microsoft.com/playwright/python:v1.65.2-noble
PORT=18450
DEMO=$(mktemp -d "${TMPDIR:-/tmp}/certkeeper-demo.XXXXXX")
mkdir -p docs/screenshots

python3 tools/demo/make-demo-config.py "$DEMO"
swift build --product certkeeper-server
CERTKEEPER_CONFIG_DIR="$DEMO" CERTKEEPER_PORT=$PORT CERTKEEPER_SCHEDULE=off \
  .build/debug/certkeeper-server > "$DEMO/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; wait $SERVER 2>/dev/null; rm -rf "$DEMO"' EXIT
for _ in $(seq 1 30); do curl -fsk "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done

docker run --rm --add-host=host.docker.internal:host-gateway \
  -e CERTKEEPER_URL="https://host.docker.internal:$PORT" \
  -v "$PWD/tools/demo:/demo:ro" -v "$PWD/docs/screenshots:/out" \
  "$PLAYWRIGHT_IMAGE" sh -c 'pip install -q playwright==1.65.2 && python3 /demo/screenshots.py /out'
echo "Screenshots in docs/screenshots"
