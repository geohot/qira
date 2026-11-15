#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

uv run pytest -v

# integration test (needs the QEMU tracer)
if [ ! -e tracers/qemu/qira-x86_64 ]; then
  echo "*** no QEMU tracer, skipping the integration test"
  exit 0
fi
./qira qira_tests/bin/loop &
QIRA_PID=$!
trap 'kill $QIRA_PID' EXIT
echo "qira pid is $QIRA_PID"
sleep 2

curl -s http://localhost:3002/ | grep "<title>qira</title>"

echo "tests pass"
