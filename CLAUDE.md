# QIRA fork: modernisation

Goal: run QIRA (timeless debugger) on Debian 13.
Scope: recording Linux and Windows binaries. Other arches/features are out of scope unless asked.

## Current state
- Code is upstream QIRA 1.4: Python 2.7, 2019-pinned deps, QEMU tracer from geohot/qemu (branch qira).
- Don't run install.sh: it targets Ubuntu 16.04 and uses sudo.
- Working legacy reference: podman image qira-legacy. Ask before running it.

## Rules
- Python 3 only; use ./venv.
- Work on feature branches off develop. You commit; I push.

## Layout
- middleware/: Python backend (Flask + Socket.IO), entry point middleware/qira.py
- middleware/qiradb/: Cython trace database
- tracers/qemu/: QEMU user-mode tracer
- tracers/pin/: Intel PIN tracer
- web/: browser UI on port 3002
