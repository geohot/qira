#!/usr/bin/env bash
# Build the QIRA images: qira:debian13 (debian:13) and qira:ubuntu26.04 (ubuntu:26.04).
#   docker/build.sh                    # both, with podman if installed, else docker
#   BASES="debian:13" docker/build.sh  # only one
#   ENGINE=docker docker/build.sh --target test   # extra arguments go to `build`
set -euo pipefail
cd "$(dirname "$0")/.."

ENGINE=${ENGINE:-$(command -v podman || command -v docker || true)}
[ -n "$ENGINE" ] || { echo "needs podman or docker" >&2; exit 1; }
BASES=${BASES:-"debian:13 ubuntu:26.04"}

for base in $BASES; do
  tag="qira:${base//:/}"   # debian:13 -> qira:debian13
  echo "== $tag (BASE=$base)"
  "$ENGINE" build -f docker/Dockerfile --build-arg "BASE=$base" -t "$tag" "$@" .
done
