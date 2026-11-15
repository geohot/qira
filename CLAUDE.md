# QIRA fork: modernisation

Goal: run QIRA (timeless debugger) on Debian 13.
Scope: recording Linux and Windows binaries. Other arches/features are out of scope unless asked.

## Current state
- Code is upstream QIRA 1.4 ported to Python 3 (Task 1): a uv project (`pyproject.toml`, `uv.lock`),
  installed as package `qira`: `src/qira/` (new code) and `qira.legacy` (mapped from middleware/,
  static2/, web/). QEMU tracer from geohot/qemu (branch qira).
- Don't run install.sh: it targets Ubuntu 16.04 and uses sudo.
- Legacy reference: podman image qira-legacy. You can't run it; reference output is in samples/legacy/.
  Ask me to run anything else against it.
- Work queue: UPGRADE.md "Task queue". When asked to do Task N, follow its rules there.
- Clean break: the modernized QIRA keeps no legacy code. `qira.legacy` only bridges the gap and is
  deleted in Task 6; don't build new features on it. Overall order: the table at the top of UPGRADE.md.

## Rules
- Python 3 only; use uv (`uv sync`, `uv run pytest`, `uv run qira …`). The env is `.venv/`.
- Dev shell: devenv (`devenv.nix`) + direnv (`.envrc`). Settings (`QIRA_*`) live in `.env` (template `.env.example`);
  your commands don't go through direnv: prefix them with
  `export PATH=$PWD/.devenv/profile/bin:$PATH UV_CACHE_DIR=$TMPDIR/uv-cache UV_PYTHON_DOWNLOADS=never SE_CACHE_PATH=$PWD/.cache/selenium SE_OFFLINE=true`
  and use `uv run --env-file .env …`.
- Sandbox: `/tmp/qira_logs` and `/tmp/qira_asm` are writable (the tracer's fixed paths). A server and its
  client must run in the same command. Status, open issues and assumptions: top of UPGRADE.md.
- Work on feature branches off develop. You commit; I push.

## Layout
- middleware/: Python backend (Flask + Socket.IO), entry point middleware/qira.py
- middleware/qiradb/: Cython trace database, compiled by setup.py during `uv sync`
- tracers/qemu/: QEMU user-mode tracer
- tracers/pin/: Intel PIN tracer
- web/: browser UI on port 3002
