#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

# ned's tests, which are really awesome
# why weren't these used?
cd tests_auto
#./autogen-extras.sh
#python autogen.py --dwarf --all
uv run python autogen.py --dwarf
cd ../
uv run python static2/testing.py
