#!/usr/bin/env bash
# Run the test suite inside each image (the `test` stage), then check that the runtime
# image starts. Same BASES/ENGINE variables as build.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

ENGINE=${ENGINE:-$(command -v podman || command -v docker || true)}
[ -n "$ENGINE" ] || { echo "needs podman or docker" >&2; exit 1; }
BASES=${BASES:-"debian:13 ubuntu:26.04"}

for base in $BASES; do
  tag="qira:${base//:/}"
  echo "== tests on $base"
  "$ENGINE" build -f docker/Dockerfile --build-arg "BASE=$base" --target test -t "$tag-test" .
  echo "== $tag starts"
  "$ENGINE" run --rm "$tag" --help > /dev/null
done
echo "UI: $ENGINE run --rm -p 3002:3002 qira:debian13   then open http://localhost:3002"
