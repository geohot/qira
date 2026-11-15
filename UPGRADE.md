# QIRA Upgrade Plan

This document describes how QIRA moves from its current state (v1.4, Ubuntu 14.04/16.04 era) to a
modern, supported stack that runs on current Linux distributions and in Docker, and that can trace
both **Linux** and **Windows** binaries.

The upgrade is staged. Each stage builds on the previous one and must leave the project usable:

| Stage | Scope | Depends on |
|-------|-------|------------|
| 0 | Baseline, golden traces, repo hygiene | — |
| 1 | **Core**: QEMU plugin tracer, Wine path for Windows, qiradb build fix, Python 3 core package | 0 |
| 2 | **Server**: FastAPI + pydantic, click CLI, pydantic-settings/.env, WebSocket streaming, Docker | 1 |
| 3 | **Frontend**: React + TypeScript, REST + WebSocket | 2 |
| 4 | qiradb rewrite in Rust (PyO3) | 1 (conformance suite) |
| 5 | Windows-native tracer (DynamoRIO) | 1, 2 |

Optional improvements that are not required for the upgrade (AI assistance, the C++/nanobind
modernization of qiradb, debugger integrations, …) are listed in [TODO.md](TODO.md).

Before the staged plan starts, four short tasks get the legacy code running on Debian 13 and
answer the tracer question. They are listed in the [Task queue](#task-queue-debian-13-track) below.

---

## Status, open issues and assumptions (updated 2026-11-15)

### Where we are

* **Task 1 is done** on `feature/py3-middleware` ([report](docs/tasks/1-py3-middleware.md)): the
  legacy middleware, qiradb and static2 run on Python 3.13, packaged as a uv project
  (`pyproject.toml`, `uv.lock`, `uv tool install .` works), 21 tests pass, Socket.IO smoke test passes.
  It is merged into `develop`. Follow-ups on `feature/task1-followups` (not merged yet): the
  Pillow/zlib startup fix (I10) and the legacy bugs from I7, see the
  [report](docs/tasks/1-py3-middleware.md#follow-ups-on-featuretask1-followups).
* **Development environment** (follow-up to Task 1): devenv (`devenv.nix`, `devenv.yaml`,
  `devenv.lock`) provides Python 3.13, uv and the compiler; direnv (`.envrc`) enters it and loads
  the `QIRA_*` settings from `.env` (template `.env.example`). Verified on devserver-01: the shell
  loads, `uv sync` builds qiradb with the Nix toolchain, the tests pass.
* **Sandbox:** `.claude/settings.json` allows writing `/tmp/qira_logs` and `/tmp/qira_asm`, and QIRA
  now empties/truncates those paths instead of deleting them (they are mount points in the sandbox).
  Verified in a new session (2026-11-15): both paths are writable, and `./qira` plus
  `smoke_socketio.py` pass against a trace in `/tmp/qira_logs`.

### What is next

1. **User:** merge `feature/task1-followups` into `develop` (and push). Keep `/tmp/qira_logs` and
   `/tmp/qira_asm` present (`~/.config/user-tmpfiles.d/qira.conf` recreates them at login).
   `/tmp/qira_binary` is no longer used; delete the stale symlink with `rm /tmp/qira_binary`.
2. **Task 2** (compare traces with the legacy capture) is the recommended next task: it is the only
   check of the port against the reference, and it needs just the podman copy listed in Task 2.
3. **Task 3** (tracer assessment) has no prerequisites and can run before, after or in a separate
   session. It now also checks whether the tracer can come from Nix (devenv) instead of apt.
4. **Task 4** (changed, see below) needs Tasks 1 and 3.
5. Then Stage 0. Parts of it (and of Stage 1C) were already done in Task 1; the stage sections are
   marked.

### Open issues

| # | Issue | Effect | Handled in |
|---|-------|--------|------------|
| I1 | The QEMU and PIN tracers hardcode `/tmp/qira_logs/` and `/tmp/qira_asm`. `QIRA_TRACE_DIR`/`QIRA_ASM_FILE` only move what the middleware reads. | One capture at a time per host; captures must be copied out of `/tmp/qira_logs`. | Task 2 works with it; Stage 1A (per-run paths as plugin args) removes it. |
| I2 | No working tracer on the host. `tracers/qemu/qira-*` are broken symlinks; the only build is the Ubuntu 16.04 binary in `qira-legacy`. | No live tracing until the user copies it (Task 2) or Task 3/4 provide one. | Task 2 (copy), Task 3 (decision), Task 4 (install). |
| I3 | Claude's sandbox: every command has its own network namespace (a server and its client must run in one command, with a `trap` that stops the server); only the listed domains are reachable (`pypi.org`, `files.pythonhosted.org`, `github.com`), so no `cache.nixos.org`, `gitlab.com` or `download.qemu.org`; sandbox setting changes need a new session; the `/tmp` paths must exist before the session starts. | Claude cannot change the devenv shell (new Nix packages) or download QEMU tarballs; the user enters the shell once after `devenv.nix` changes. | Rules 4 and 9. Add domains in `.claude/settings.json` if a task needs them. |
| I4 | `uv tool install .` does not contain the tracer. **Partly fixed** on `feature/task1-followups`: an installed copy now looks in `${XDG_DATA_HOME:-~/.local/share}/qira/tracers/` (and `…/libs/`), a checkout in its own `tracers/`. | Nothing installs a tracer there yet. | Task 4 (install the tracer into that folder). |
| I5 | `docker/Dockerfile` and `install.sh` still use Python 2 and `requirements.txt`. | The `qira-legacy` image must be built from a commit before Task 1 (e.g. `862c3aa`). | Task 4 (`install.sh`), Stage 2 (Docker). |
| I6 | ~~The legacy modules are importable as `qira.*`, clashing with the planned `src/qira/core` layout.~~ **Fixed** on `feature/task1-followups`: `src/qira/` is the top-level package; the legacy code is `qira.legacy` (`middleware/`), `qira.legacy.static2`, `qira.legacy.web`; console script `qira.legacy.qira:main`, `python -m qira` still works. | — | Stage 1D adds `qira.core` next to it and replaces `qira.legacy` modules as they land. |
| I7 | ~~Legacy bugs: `doanalysis` arguments, bare `except` hiding "already running as server", `--flush-cache` running `rm -rfv /tmp/qira*`, `os.fork()` from a threaded process, the global `/tmp/qira_binary` symlink.~~ **Fixed** on `feature/task1-followups`. | — | Stage 1D/2 still replace this code. |
| I8 | The web UI (with the socket.io 4 client) was not opened in a real browser. | A UI regression would go unnoticed. | User check on port 3012, or Task 2 with the user. |
| I9 | Claude's commands do not go through direnv, so `uv` and the `.env` settings are not loaded automatically. | Commands must set them explicitly. | Rule 4. |
| I10 | `.venv/` is built against the Nix Python (`/nix/store/…`). | `./qira` also works outside the devenv shell, but after `devenv update` the next shell entry re-syncs `.venv`. Do not mix with a Debian-Python `.venv`. The Nix Python does not search Debian's library paths: Pillow's wheel needs the system `libz.so.1`, so `qira_analysis.py` imports `zlib` before PIL (checked by `qira_tests/test_startup.py`). Other wheels that link system libraries need the same care. | Rule 4. |

### Assumptions

* A1 — Target is Debian 13 on x86_64 (devserver-01). Nix (multi-user), devenv and direnv are installed
  by the user; Claude never installs system software.
* A2 — Python 3.13 from nixpkgs is the reference interpreter; `requires-python = ">=3.12"` stays so
  Debian's own Python 3.13 also works without devenv.
* A3 — Settings are `QIRA_*` environment variables, set in `.env`. The names in use
  (`QIRA_TRACE_DIR`, `QIRA_ASM_FILE`, `QIRA_STATIC_CACHE_DIR`, `QIRA_TRACER_DIR`, `QIRA_LIBS_DIR`) stay
  valid when Stage 2 moves to pydantic-settings (as aliases where the field name changes).
* A4 — The trace format (§1) does not change before Stage 1A; `samples/legacy/` is the ground truth
  for the legacy behaviour.
* A5 — Only the user runs podman, sudo, `git push` and merges.
* A6 — The legacy `web/` UI stays as it is until Stage 3; only the Socket.IO client was updated.
* A7 — Windows binaries remain view-only until Stage 1B.

---

## Task queue (Debian 13 track)

Each task is written so that it can be handed to Claude with a one-line prompt, for example
**"Do Task 2 in UPGRADE.md"**, and finished without anyone at the keyboard.

| # | Task | Branch | Needs in `develop` | Needs from the user first |
|---|------|--------|--------------------|---------------------------|
| 1 | [x] Port `middleware/` to Python 3, package it with `pyproject.toml`/uv (installable as a tool), get the tests passing ([report](docs/tasks/1-py3-middleware.md)) | `feature/py3-middleware` | — | — |
| 2 | [ ] Compare the port's traces of `qira_tests/bin/loop` with `samples/legacy/` and list the differences | `feature/trace-compare-loop` | Task 1 | Legacy tracer binary copied to the host (see Task 2); a Claude session started after the sandbox change |
| 3 | [ ] Assess the QEMU tracer: rebase the qira patches onto current QEMU, or replace the tracer | `feature/tracer-assessment` | — | — |
| 4 | [ ] Install on Debian 13: `install.sh` as a user install (uv tool + tracer), devenv for development (changed after Task 1) | `feature/install-debian13` | Tasks 1 and 3 | Enter the devenv shell once if Task 3 adds Nix packages |

Task 1 is done. Tasks 2 and 3 can run in either order (Task 2 is recommended first). Run one task per session.

### Rules for every task

1. **Branch.** Start from the local `develop`: `git switch develop && git switch -c <branch>`.
   Use the branch name from the table. If the branch already exists, continue on it.
   If a task listed under "Needs in `develop`" is not merged into `develop`, stop and say so in the
   final message. Do not branch off another task's branch.
2. **Commit, don't push.** Commit in small steps on the task branch. The user pushes and merges.
   The last commit ticks the task's box in the table above and links the task report.
3. **No root.** No `sudo`, no `apt-get install`, nothing written outside the repo, `$TMPDIR` and the
   tracer's `/tmp/qira_logs` and `/tmp/qira_asm`.
   If a system package is missing, list the exact `sudo apt-get install …` line in the report and
   carry on with whatever does not need it.
4. **Python.** Python 3 only (Debian 13 ships 3.13), managed with **uv** since Task 1:
   `uv sync` creates `.venv/`, `uv run pytest`, `uv run qira …` (or `./qira`). Dependencies live in
   `pyproject.toml` + `uv.lock`; there is no `requirements.txt` any more. The shell (Python 3.13, uv,
   compiler) is defined in `devenv.nix` and entered with direnv (`.envrc`), which also loads the
   `QIRA_*` settings from `.env` (template: `.env.example`). Claude's commands do not go through
   direnv; start them with
   `export PATH=$PWD/.devenv/profile/bin:$PATH UV_CACHE_DIR=$TMPDIR/uv-cache UV_PYTHON_DOWNLOADS=never`
   and use `uv run --env-file .env …`. Claude cannot change the devenv shell itself (the Nix cache
   is not reachable from the sandbox): edit `devenv.nix` and ask the user to enter the shell once.
   Do not run the old `install.sh` (it targets Ubuntu 16.04 and calls sudo).
5. **Legacy reference.** Do not run podman. Never modify or delete anything in `samples/legacy/`;
   it is the reference capture. Put new captures in other folders under `samples/` (the whole
   `samples/` folder is excluded from git via `.git/info/exclude`, so nothing there is committed).
6. **Ports.** The user may have the legacy UI running on port 3002. Use `--web-port 3012` (and
   `--socat-port 4010`) for anything this task starts, and stop every process it started before
   finishing.
7. **Report.** Write `docs/tasks/<n>-<short-name>.md` with: what was done, how it was verified
   (commands and results), what could not be verified and why, open questions for the user, and
   anything the next task needs to know. If the task is blocked, still commit the report with the
   blocker and the exact command the user has to run.
8. **Stay in scope.** Do not start the staged plan (FastAPI, React, the `src/qira/core` layout, …)
   inside these tasks. (Packaging with `pyproject.toml`/uv was pulled into Task 1 on request.) If the
   work shows that part of this plan is wrong, note it in the report and update the relevant section
   of this file (including [Status, open issues and assumptions](#status-open-issues-and-assumptions-updated-2026-11-15))
   in the same branch.
9. **Sandbox.** Each command runs in its own network namespace: start a server and its client in
   the **same** command, e.g. `./qira … & SRV=$!; trap 'kill $SRV' EXIT; …`, and never leave a
   process running. Only `pypi.org`, `files.pythonhosted.org` and `github.com` are reachable; if a
   task needs another host, stop and ask the user to add it to `.claude/settings.json`.

### Legacy reference (podman image `qira-legacy`)

The legacy build (Ubuntu 16.04, Python 2.7, geohot QEMU fork) runs in podman. Only the user runs it.

* While it runs, the UI is at <http://devserver-01:3002>.
* `samples/legacy/` is mounted over the container's trace folder (`/tmp/qira_logs`). QIRA normally
  wipes that folder on start and cannot delete a mount point, so it is started with
  `--no-delete-runs`.
* QIRA treats every file in the trace folder as a numbered trace, so nothing else may live there.
  The console log of a capture is kept next to it, e.g. `samples/loop-console.log`.
* The user clears old runs between captures with `rm -rf ~/src/qira/samples/legacy/*`.
  Claude never runs this.
* Current capture: `samples/legacy/{0,0_base,0_env,0_strace}` from `qira qira_tests/bin/loop`
  (paths inside the container start with `/qira/`, libc is Ubuntu 16.04's `ld-2.23.so`), console
  output in `samples/loop-console.log`.
* If a task needs another legacy capture, it stops and lists exactly what to capture (binary,
  arguments, which files to copy where).

---

### Task 1 — Port `middleware/` to Python 3

**Branch:** `feature/py3-middleware` · **Report:** `docs/tasks/1-py3-middleware.md`

**Status:** done. The "Done when" checks below were run with uv instead of `./venv` (see the
report). Follow-ups on the same branch: devenv/direnv/`.env`, and mount-safe cleanup of the
`/tmp` trace paths.

**Goal:** the legacy backend runs on Python 3.13 with current dependencies, and the test suite
passes. Behaviour, the trace format and the Socket.IO events stay the same.

**Changed on request (done this way):** instead of `./venv` + `requirements.txt`, QIRA is a uv
project (`pyproject.toml`, `uv.lock`) that installs as the `qira` package with a `qira` console
script, so both `uv sync` (development, editable) and `uv tool install .` work. qiradb is compiled
at install time by `setup.py` (Cython 3) instead of `pyximport`, which is part of Stage 1C step 1.
The steps below are kept as written; the report says where the result differs.

**Scope**

* `middleware/*.py`, `middleware/qiradb/` (Cython + C++), and `static2/` (imported by
  `qira_program.py` and covered by `test_static2.py`). The `qira` launcher script if needed.
* `requirements.txt`: pin current versions that install on Python 3.13. Drop what is not used or is
  in the standard library (`ipaddr` → `ipaddress`, `nose`, check `socketIO-client`, `six`,
  `certifi`/`chardet`/`idna`/`urllib3` unless something still needs them). Cython 3, capstone 5,
  pyelftools ≥ 0.33. Add `pytest`.
* `web/` only where the Socket.IO upgrade forces it (see below). No UI changes.
* `run_tests.sh`: replace `nosetests -v -s` with `pytest`.

**Steps**

1. Inventory: `grep` for Python 2 constructs (`print ` statements, `xrange`, `iteritems`,
   `has_key`, `urllib.unquote`, `cPickle`, `string.` helpers, integer `/`, `str`/`bytes` mixing on
   files, sockets and `struct`). Mind binary I/O in `qira_log.py`, `qira_program.py` (strace and
   `_base` parsing, `/proc` reads), `qira_socat.py` and `static2/`.
2. qiradb: make it compile on Debian 13's GCC with Cython 3. Replace the
   `__cplusplus == 201103L` check in `Trace.h` with `std::unordered_map` + a hash for the pair key,
   fix `str`/`bytes` in `qiradb.pyx`. `pyximport` may stay for now (a proper wheel build is Stage 1C);
   if it does not work with Cython 3, add a minimal `setup.py` build instead and document it.
3. Socket.IO: the browser client is vendored in `web/client/compatibility/socket.io.min.js`
   (check its version). Flask-SocketIO 5 / python-socketio 5 only talk to JS client 3.x/4.x.
   Preferred: Flask-SocketIO 5 and replace the vendored client with socket.io 4.x (same file name,
   no other `web/` changes). Async mode: keep gevent if it works on 3.13, otherwise `threading`.
   Record the choice in the report.
4. Make the trace folder configurable: `QIRA_TRACE_DIR` environment variable overrides
   `TRACE_FILE_BASE` in `qira_config.py` (default unchanged). Task 2 needs this. Same for
   `QIRA_STATIC_CACHE_DIR`.
5. Tests: convert `qira_tests/` to pytest. `test_qiradb.py` and `test_static2.py` must pass.
   `test_qira_program_runs.py` needs the QEMU tracer, which does not exist on this host
   (`tracers/qemu/qira-*` are broken symlinks): mark it `skipif` when `tracers/qemu/qira-x86_64`
   does not resolve, with that reason. Add small tests for the code paths touched in step 1 where
   cheap (strace line parsing, `_base` parsing, `qira_log` read/write round trip).
6. Smoke test without a tracer: copy `samples/legacy/` to `$TMPDIR/legacy-copy/`, run
   `QIRA_TRACE_DIR=$TMPDIR/legacy-copy ./qira --no-run --no-delete-runs --web-port 3012 qira_tests/bin/loop`,
   then check `curl -s localhost:3012/ | grep '<title>qira</title>'` and a Socket.IO round trip
   with the python-socketio client (connect to namespace `/qira`, request registers/memory at a few
   clnums, check that replies arrive). Keep that client as `qira_tests/smoke_socketio.py`.
   If `--no-run` does not load existing traces, say how the port behaves and what the legacy code
   does in the same case.

**Done when**

* `./venv/bin/pip install -r requirements.txt` works in a fresh venv (`python3 -m venv $TMPDIR/v`).
* `./venv/bin/python -m pytest qira_tests` passes (tracer test skipped with a reason).
* `./venv/bin/python -m compileall -q middleware static2` prints nothing.
* The smoke test in step 6 passes.
* The report lists what was not checked (the UI in a real browser, tracing a live binary).

### Task 2 — Compare the port's trace of `loop` with the legacy capture

**Branch:** `feature/trace-compare-loop` · **Report:** `docs/tasks/2-trace-compare-loop.md`

**Goal:** a list of every difference between a trace of `qira_tests/bin/loop` taken with the
Python 3 middleware and `samples/legacy/`, each one explained as expected or as a bug in the port.

**Before going offline, the user provides a tracer.** The geohot QEMU fork does not build on
Debian 13 (that is Task 3), so copy the binary from the legacy image:

```bash
cd ~/src/qira
mkdir -p tracers/qemu/qemu/x86_64-linux-user samples/sysroot-xenial/lib
podman create --name qira-legacy-cp qira-legacy
podman cp qira-legacy-cp:/qira/tracers/qemu/qemu/x86_64-linux-user/qemu-x86_64 \
          tracers/qemu/qemu/x86_64-linux-user/qemu-x86_64
# optional, gives the same libc as the legacy capture:
podman cp qira-legacy-cp:/lib/x86_64-linux-gnu samples/sysroot-xenial/lib/
podman cp qira-legacy-cp:/lib64 samples/sysroot-xenial/lib64
podman rm qira-legacy-cp
```

After that `tracers/qemu/qira-x86_64` resolves. If it is missing when the task starts, do only the
read-side comparison (step 3) and report the blocker with the commands above.

**Steps**

1. Check the tracer: `ldd tracers/qemu/qira-x86_64` (it was linked on Ubuntu 16.04; list missing
   libraries) and that it runs `qira_tests/bin/loop` on its own.
2. Capture with the port into its own folder (never `samples/legacy/`). The tracer always writes
   to `/tmp/qira_logs/` and `/tmp/qira_asm` (issue I1); the sandbox allows both. First check that
   they are writable (`touch /tmp/qira_logs/.w && rm /tmp/qira_logs/.w`); if not, the session was
   started before the sandbox change: stop and say so. Capture in one command and copy the result:
   `timeout 60 ./qira --web-port 3012 --socat-port 4010 qira_tests/bin/loop > samples/port-console.log 2>&1; cp -r /tmp/qira_logs samples/port`
   (stop earlier once the trace stops growing, if that is easy to detect).
   The legacy `_base` also lists `/tmp/qira_logs/0_env` as a mapping, so loading a copied trace
   from another folder misses that one region. If the sysroot was provided and the port can pass an
   ld prefix to QEMU (`-L` / `QEMU_LD_PREFIX`; see how `qira_program.py` uses `libs/` from
   `fetchlibs.sh`), take a second capture with it in `samples/port-xenial/`. That one should match
   the legacy capture closely, the first one shows the effect of Debian 13's libc.
3. Read side: load `samples/legacy/0` with the ported qiradb and `qira_log` and check the numbers
   against `samples/loop-console.log` (max clnum, names found, base addresses).
4. Write `qira_tests/compare_traces.py <dirA> <dirB>` (kept for later stages) that compares:
   `logstate` header fields; record counts per type (`I`/`L`/`S`/`R`/`W`, syscall flag);
   the instruction sequence of the main binary (pc per clnum, normalised by module base from
   `_base`); register values and memory writes at matched instructions; the syscall list from
   `_strace` (names, arguments with pointers normalised, return values); the module list in
   `_base`; `_env`. Output a readable summary plus the first N differing records per category.
5. Classify each difference: expected (ASLR/base addresses, pid, container paths `/qira/…` vs host
   paths, libc version, environment/hostname) or caused by the port (different arguments or
   environment passed to QEMU, parsing differences, wrong `_base`/strace handling). For the second
   kind, fix it on this branch if it is small and clearly a port bug, otherwise list it as an issue.

**Done when:** the report has a differences table (category, legacy, port, cause, expected?) for
each capture, the script is committed, and every "caused by the port" item is fixed or listed.

### Task 3 — Assess the QEMU tracer

**Branch:** `feature/tracer-assessment` · **Report:** `docs/tracer-assessment.md`
(plus a short `docs/tasks/3-tracer-assessment.md` pointing to it)

**Goal:** a decision the user can sign off: **rebase** the qira patches onto current QEMU, or
**replace** the tracer (QEMU TCG plugin as in §3 1A, or something else). Assessment only: do not
change the tracer used by the middleware.

**Inputs:** `extra/qemu_mods/` (`tci.c`, `main.c`, `strace.c`, `disas.c`, `gen_patch.sh`),
`tracers/qemu_build.sh` (clones `geohot/qemu`, branch `qira`, QEMU 2.x with
`--enable-tcg-interpreter`), the trace format in §1, and §3 1A of this file.

**Questions to answer**

1. How large is the qira delta? Clone `geohot/qemu@qira` and the upstream tag it is based on into
   `$TMPDIR` (use the GitHub mirror `github.com/qemu/qemu`; gitlab.com is not reachable from the
   sandbox. If the network is blocked, work from `extra/qemu_mods/` and say so) and list the
   changed files and lines, grouped by feature (tracing hooks, kernel-write tracking, strace,
   `-qirachild` fork/replay, base map, disassembly, gate/filter).
2. What does a rebase onto the current QEMU release cost? TCI was rewritten in QEMU 6.0 and
   linux-user/TCG internals moved a lot since 2.x. Estimate per feature, and note that TCI is slow.
3. Can the plugin API of the current QEMU release do everything the trace format needs?
   Check `qemu-plugin.h` for: per-instruction callbacks, memory access values, register read,
   memory read, syscall callbacks, and the register/memory **write** functions needed for
   fork-at-clnum replay. Name the QEMU version each first appeared in. List gaps and workarounds.
4. Does Debian 13's `qemu-user` package have plugin support and ship `qemu-plugin.h`?
   (`apt-get download qemu-user qemu-system-common` and `dpkg -c`/`dpkg -x` into `$TMPDIR`
   needs no root; or `apt-cache show`.) If yes, the tracer could be a plugin loaded into the
   distribution's QEMU with no QEMU build at all. **Added after Task 1:** answer the same for
   nixpkgs' `qemu` (or `qemu-user`) as pinned by `devenv.lock` (the nixpkgs source on GitHub is
   reachable; the Nix cache is not, issue I3). If it fits, the tracer's QEMU and build tools can be
   `packages` in `devenv.nix`, which needs no sudo at all.
5. Briefly: other options (DynamoRIO on Linux, Intel PIN's licence and the state of
   `tracers/pin/`, Valgrind) and why they win or lose against the plugin.
6. What Debian 13 packages, or nixpkgs packages for `devenv.nix`, each option needs to build
   (for Task 4).

**Spike (optional, stop after about two hours of work):** build a minimal plugin that writes
`I` and `S` records in the 24-byte format for `qira_tests/bin/loop`, using Debian's QEMU if it
has plugin support, otherwise upstream QEMU built in `$TMPDIR` with
`--target-list=x86_64-linux-user --enable-plugins`. Compare the instruction count with
`samples/legacy/0`. Keep spike code under `tracers/qemu-plugin/spike/` and say in the report that
it is a spike. If build dependencies are missing, stop the spike and list them.

**Done when:** `docs/tracer-assessment.md` has the answers above, a recommendation with effort
estimate and risks, the build dependencies, the exact `install.sh` step Task 4 should use, and
§3 1A of this file is updated if the findings change it.

### Task 4 — Install on Debian 13 (changed after Task 1)

**Branch:** `feature/install-debian13` · **Report:** `docs/tasks/4-install-debian13.md`

**Why it changed:** development now uses devenv + uv (`devenv.nix`, `.envrc`, `.env`), so
`install.sh` no longer has to build a Python environment. What is still missing is an install for
people who only want to *use* QIRA, and a tracer for both (issues I2, I4).

**Goal:** on a fresh Debian 13 checkout, `./install.sh` installs a working `qira` command
(including the tracer) as a normal user, and the devenv shell can trace as well.

**Requirements**

* `#!/usr/bin/env bash`, `set -euo pipefail`, `--help`, idempotent (a second run is quick and safe).
* **No sudo inside.** Check system packages with `dpkg-query -W`. If any are missing, print one
  line `sudo apt-get install -y …` with exactly the missing packages and exit non-zero. Packages
  depend on Task 3's recommendation (none if the tracer comes from Nix).
* Python: require `uv` on `PATH` (from the devenv shell or the official installer into
  `~/.local/bin`; print how and exit non-zero if missing), then `uv tool install --force .`.
* Tracer: the step recommended in `docs/tracer-assessment.md`, installed into
  `${XDG_DATA_HOME:-$HOME/.local/share}/qira/tracers/`, behind `--with-tracer` (or `--no-tracer`,
  whichever Task 3 recommends as default). Never fails the install when the tracer is skipped, but
  says so. If Task 3 recommends a Nix-provided QEMU, add it to `devenv.nix` as well, so the dev
  shell can trace.
* Code change: **done** on `feature/task1-followups`. `qira_config.default_dir()` uses that data
  folder for installed copies (the package is not mapped from a checkout's `middleware/`), so
  `QIRA_TRACER_DIR` is no longer needed; `.env.example` documents it, `test_default_tracer_dir`
  covers it.
* Remove the Ubuntu 14.04/16.04, Arch, Fedora and macOS branches and the `requirements.txt`/venv
  code; on anything other than Debian/Ubuntu, print what is needed and exit.
* `--skip-tests` turns off a final `uv run pytest` (run from the checkout).
* Update the install section of `README.md` (development: devenv; usage: `./install.sh`).

**Verification**

* `shellcheck install.sh` if available (it can be added to `devenv.nix` by the user; otherwise say so).
* In a fresh clone, with uv's tool folders in `$TMPDIR`:
  `git clone -b feature/install-debian13 . $TMPDIR/qira-install && cd $TMPDIR/qira-install && UV_TOOL_DIR=$TMPDIR/uv-tools UV_TOOL_BIN_DIR=$TMPDIR/uv-bin XDG_DATA_HOME=$TMPDIR/share ./install.sh`.
  Run it twice. Then check `$TMPDIR/uv-bin/qira --help` and that the installed tool finds the tracer
  (`python -c` on `qira_config.TRACER_DIR` inside the tool environment).
* Missing-package path: the script appends `$QIRA_EXTRA_PKGS` to its package list, so
  `QIRA_EXTRA_PKGS=does-not-exist ./install.sh` must print the apt line and exit non-zero.

**Done when:** both runs finish without a sudo prompt, the installed `qira` finds its tracer
without `QIRA_TRACER_DIR`, the tests pass, and the report shows the output.

---

## 1. Current-state assessment

### Components

| Component | Location | State |
|-----------|----------|-------|
| Tracer | `tracers/qemu_build.sh` → `geohot/qemu@qira`; patches in `extra/qemu_mods/{tci.c,main.c,strace.c,disas.c}` | QEMU 2.x fork using the TCG interpreter (TCI). Does not build on modern toolchains (README notes 18.04 already fails). `tracers/qemu/qira-*` are symlinks into the `qemu/` clone, so they are broken until it is built; on Debian 13 the only working build is in the `qira-legacy` podman image (see Task queue). |
| Alternative tracer | `tracers/pin/qirapin.cpp`, `tracers/pin_build.sh` | Intel PIN tool, used on macOS / optional on Linux. Tied to an old PIN release. |
| Trace database | `middleware/qiradb/` (`Trace/Trace.{h,cpp}`, `qiradb.pyx`) | C++ reader of the mmap'd change log. Since Task 1: built by `setup.py` (Cython 3, C++17) during `uv sync`, `std::unordered_map` on every compiler. Memory history is a `std::map<Clnum,uint8_t>` **per byte**, which uses a lot of RAM. |
| Middleware | `middleware/*.py` | Since Task 1: Python 3.13, Flask 3 + Flask-SocketIO 5 (threading mode), installed as package `qira.legacy` (since the Task 1 follow-ups). Still: argparse CLI, process control via `os.fork`/`os.execvp`, global mutable config in `qira_config.py` (paths now overridable with `QIRA_*` variables / `.env`). |
| Static analysis | `static2/` | Ported to Python 3 in Task 1 (capstone 5, pyelftools 0.33). Pickle-based cache in `/tmp/qira_static_cache/`. |
| Frontend | `web/` | jQuery 2, a Meteor shim (`fakemeteor.js`), wcDocker, socket.io client 4.8 (updated in Task 1). |
| Dependencies / dev env | `pyproject.toml`, `uv.lock`, `devenv.nix`, `.envrc`, `.env.example` | Since Task 1: current versions locked by uv; devenv + direnv dev shell; `requirements.txt` removed. |
| Install / CI | `install.sh`, `docker/Dockerfile` (ubuntu:16.04), `.travis.yml`, `run_tests.sh` | Installs `python` (2), builds QEMU. Travis is dead. Since Task 1 the Python side is a uv project (`pyproject.toml`, `uv.lock`, `uv run pytest`); `install.sh` and the Dockerfile still expect `requirements.txt` until Task 4 / Stage 2, so the `qira-legacy` image must be built from a commit before Task 1 (e.g. `862c3aa`). |

### Trace format (must be preserved or versioned)

* **Change log** `TRACE_FILE_BASE/<id>`: array of 24-byte records `struct change { u64 address; u64 data; u32 clnum; u32 flags; }`
  (`middleware/qira_log.py`, `Trace.h`). Record 0 is a `logstate` header
  (`change_count`, `changelist_number`, `is_filtered`, `first_changelist_number`, `parent_id`, `this_pid`).
* **Flags**: `IS_VALID 0x80000000`, `IS_WRITE 0x40000000`, `IS_MEM 0x20000000`, `IS_START 0x10000000`,
  `IS_SYSCALL 0x08000000`, `SIZE_MASK 0xFF` (size in bits).
  Types: `I` instruction start, `L`/`S` memory load/store, `R`/`W` register read/write.
* **Register addressing**: a register change's `address` is its byte offset into the guest
  `CPUArchState` (`track_read`/`track_write` in `tci.c`). qiradb maps it as
  `registers_[address / register_size]` for `address < register_size * register_count`
  (`Trace.cpp:212`). The register name lists in `middleware/arch.py` (with `None` padding) mirror that
  layout. **A new tracer must emit `index_in_arch_list * regsize` as the address.**
* **Kernel writes**: bytes the kernel writes into guest memory during syscalls are recorded as
  1-byte `S` changes (`track_kernel_write`).
* **Sidecar files**: `<id>_strace` (`"<clnum> <pid> <syscall text>"`), `<id>_base` (`/proc/maps`-like
  lines, used by `Trace.load_base_memory`), `<id>_mods` (memory/register edits injected at fork time),
  `<id>_images/` (PIN image dumps), and a **global** `/tmp/qira_asm` disassembly file.

### Fork / replay protocol

The `forkat` handler (`middleware/qira_webserver.py`) writes `<next_id>_mods` and re-executes the
tracer with `-qirachild "<parent> <clnum> <id>"`. The patched QEMU replays the parent log
(`run_QIRA_log_from_fd` in `tci.c`) up to `clnum`, applies the mods, and continues tracing as a new fork.
`qira_socat.py` gives the same behaviour for network services (`--server`, ports 4000/4001).

### Socket.IO surface (namespace `/qira`)

Client → server: `forkat`, `deletefork`, `doslice`, `doanalysis`, `getclnum`, `getchanges`,
`navigatefunction`, `getinstructions`, `getmemory`, `getregisters`, `setfunctionargswrap`,
`getnames`, `gotoname`, `settags`, `getstaticview`, `make`.
Server → client: `pmaps`, `maxclnum`, `arch`, `setpicture`, `strace`, `slice`, `clnum`, `changes`,
`setclnum`, `instructions`, `memory`, `registers`, `names`, `setiaddr`, `flat`, `function`.
HTTP: `/hasstatic`, `/gettagsa`, `/gettagss`, `/dot`, static files.

### Windows support today

`qira_program.py:identify_program` detects PE32/PE32+ but only "runs the server". Windows binaries
can be viewed only from a trace produced elsewhere (e.g. `tests_manual/windows/fibonacci64/`).

### Legacy to retire (after Stage 3)

`extra/` (old experiments, meteor server, CDA, website), `tracers/qemu/qira-*` prebuilt binaries,
`ida/bin` + `ida/libs` prebuilt plugins (replace later, see TODO.md), `.travis.yml`, `run_tests.sh`,
`install.sh` (replaced by Docker + `uv`; until then Task 4 keeps it working on Debian 13), `web/`, `middleware/`, `static2/`
(after porting), `fetchlibs.sh` (replace with a documented sysroot/`QEMU_LD_PREFIX` setting).

### Key risks

| Risk | Mitigation |
|------|------------|
| Upstream QEMU plugins were originally **observe-only**. Fork-at-clnum replay needs register/memory **write** APIs, which arrived only in recent QEMU releases. | Pin a QEMU version that has them; check the API version at plugin load; document a degraded mode (fork = fresh deterministic re-run without injected mods) if they are missing. |
| Per-instruction register diffing through the plugin API is slow. | Cache register handles, only read the registers listed in the arch descriptor, use per-vCPU scoreboards, and benchmark against the old tracer. |
| Wine under `qemu-user` is fragile (preloader, address-space reservations, signals). | Stage 1B starts with a time-boxed spike that has an explicit go/no-go. Stage 5 (DynamoRIO) is the fallback and long-term path. |
| qiradb memory use on long traces. | Out of scope for the upgrade (see TODO.md "qiradb C++ modernization"); Stage 4 Rust rewrite addresses it. |

---

## 2. Stage 0 — Baseline and repo hygiene

**Goal:** be able to prove that the new stack produces the same results as the old one.

1. **Golden traces.** The legacy image exists as podman `qira-legacy` (built from
   `docker/Dockerfile`, ubuntu:16.04, old QEMU fork; see [Legacy reference](#legacy-reference-podman-image-qira-legacy)).
   A first capture of `loop` is in `samples/legacy/` (local only). Capture reference traces for `qira_tests/bin/loop`, `qira_tests/bin/hello_trace`
   and a selection of `tests_auto/source-autogen/*.c` (loop, forktest, heaptest, test64, echo).
   Store them in `tests/fixtures/golden/<name>/` with the log, `_strace`, `_base` and asm.
   Also export query results (registers/memory at selected clnums) as JSON, so later stages can
   compare without the old code.
2. **Packaging.** `pyproject.toml` (Python ≥ 3.12, uv) and pytest were done in Task 1, the devenv
   shell after it. Remaining: ruff, mypy and pre-commit (devenv's `git-hooks` can run them), and a
   GitHub Actions workflow (lint, test, Docker build) to replace Travis; CI may use plain uv or
   `devenv test`.
3. **Layout.** Create the new tree next to the old code; move old code to `legacy/` only when its
   replacement lands:

   ```
   src/qira/core/        # tracer drivers, log I/O, qiradb wrapper, analysis, static
   src/qira/server/      # FastAPI app (Stage 2)
   src/qira/cli/         # click CLI
   src/qira/config.py    # pydantic-settings (Stage 2, stub in Stage 1)
   qiradb/               # native extension
   tracers/qemu-plugin/  # QEMU TCG plugin (Stage 1A)
   frontend/             # React app (Stage 3)
   tests/                # pytest suites + fixtures
   docker/               # Dockerfile, compose
   ```

**Done when:** golden fixtures are committed, `uv run pytest` runs (even with few tests), and CI is green.

---

## 3. Stage 1 — Core

**Goal:** a modern tracer and a Python 3 core library that can trace a binary and answer queries,
with no web stack involved.

### 1A. QEMU TCG plugin tracer (`tracers/qemu-plugin/`)

Replace the QEMU fork with a plugin (`qira.c` → `libqira.so`) that loads into **unmodified upstream
QEMU** `*-linux-user` builds via `-plugin`. Pin one QEMU release in the Docker build stage and check the
plugin API version at install time.

| Old (`tci.c` patch) | New (plugin API) |
|---|---|
| `IS_START` per instruction | `qemu_plugin_register_vcpu_tb_trans_cb` → per-insn `register_vcpu_insn_exec_cb`; increments clnum, records pc and size |
| `track_load`/`track_store` | `qemu_plugin_register_vcpu_mem_cb` + `qemu_plugin_mem_get_value` (value of the access) |
| `track_read`/`track_write` (registers) | `qemu_plugin_get_registers` once per vCPU, then `qemu_plugin_read_register` at instruction boundaries; diff against the previous values and emit `W` records. `R` records only if needed by analysis (measure). Map plugin register names → `arch` descriptor index so `address = index * regsize`. |
| `track_kernel_write` | `vcpu_syscall_ret` callback: for syscalls known to write user buffers (`read`, `pread64`, `recvfrom`, `recvmsg`, `readv`, `getdents64`, `fstat`/`newfstatat`, …), read the buffer with `qemu_plugin_read_memory_vaddr` and emit byte `S` records |
| `-strace` text + `strace.c` | `vcpu_syscall`/`vcpu_syscall_ret` callbacks write `<id>_strace` (`clnum pid name(args) = ret`) and a structured `<id>_syscalls.jsonl`. Track `open/openat/mmap/mmap2` directly instead of parsing text in `read_strace_file`. |
| `target_disas` → `/tmp/qira_asm` | `qemu_plugin_insn_disas` → per-run `<id>_asm` (no global file, no `flock`) |
| `write_out_base` | Write `<id>_base` at the first instruction from the ELF program headers, the interpreter and tracked mmaps; validate against `-d page` output in tests |
| `-gatetrace`, `-tracelibraries`, `is_filtered_address` heuristic | Plugin args: `gate=0x…`, `tracelibs=on`, `filter=<ranges>`. Filtering uses real module ranges (from mmap tracking) instead of the hardcoded address heuristic. |
| `-qirachild "parent clnum id"` + `run_QIRA_log_from_fd` | Plugin args `parent=`, `start_clnum=`, `id=`. Replay: until `start_clnum` the plugin overrides syscall results with the parent's (syscall filter callback + register write) and applies `<id>_mods` with the plugin write APIs. Degraded mode if the APIs are missing (see risks). |
| guest `fork()` | On `clone`/`fork` returning 0 in the child, open a new log with `parent_id` set, same as today |

**Log format:** keep the 24-byte `struct change` and the `logstate` header unchanged so the existing
reader keeps working. Add a sidecar **`<id>.meta.json`** (pydantic model in the core):
`format_version`, `tracer` (`qemu-plugin`/`dynamorio`/…), `arch`, `register_names`, `register_size`,
`big_endian`, `binary_path`, `binary_sha1`, `parent_id`, `start_clnum`, `qemu_version`.

**Architectures:** i386, x86_64, arm (armel/armhf), aarch64, mips, mipsel, ppc. riscv64 is a cheap
extra once the arch descriptors are data-driven.

**Build:** `tracers/qemu-plugin/CMakeLists.txt` (or Meson) against the pinned `qemu-plugin.h`.
The Docker builder stage compiles QEMU with
`--target-list=<arch>-linux-user,… --enable-plugins` and the plugin.

**Done when:**
* plugin traces of the golden binaries give the same instruction sequence (pc per clnum), memory
  writes and register values as the Stage 0 fixtures (allowing documented differences such as
  ASLR/base addresses);
* fork-at-clnum works on `forktest` / a modified register case;
* throughput is measured and recorded (instructions/s vs. the legacy tracer).

### 1B. Windows, part 1 — Wine under the QEMU plugin

1. **Spike (time-boxed):** run `qemu-x86_64 -plugin libqira.so,… /usr/lib/wine/wine64 fibonacci64.exe`
   (and `qemu-i386` + `wine` for 32-bit) on the chosen base image. **Go** if
   `tests_manual/windows/fibonacci{32,64}.exe` and `paris.exe` run to completion with output.
   **No-go** → skip to Stage 5 for Windows and keep only trace viewing for PE files.
2. **Module tracking:** detect the PE image and DLL mappings from the openat/mmap tracking in 1A;
   parse PE headers with LIEF (or `pefile`) for section ranges, entry point and exports.
3. **Filtering:** trace only the main PE module by default (`gate` at the PE entry point, `filter`
   = image ranges). `--trace-libraries` includes DLLs; Wine's own loader and the Unix side are never traced.
4. **Arch/OS info:** `meta.json` gets `os: "windows"`, `image_base`, and a module list; static
   analysis loads the PE (names from exports, later PDB — see TODO.md).
5. **Syscalls:** under Wine the guest makes Linux syscalls; record them as-is but mark `os=windows`
   so the frontend can label the strace panel accordingly.

**Done when:** `qira trace tests_manual/windows/fibonacci64.exe` produces a trace that the core can
query, and the instructions shown are in the PE image.

### 1C. qiradb — build fix and conformance suite (required minimum)

The full C++20/nanobind modernization has been moved to [TODO.md](TODO.md). The upgrade only needs:

1. **Build on modern Python** (done in Task 1 with `setup.py` + Cython 3 + setuptools; only the
   Docker/CI wheel build remains): replace `pyximport` / `qiradb.pyxbld` with a proper build
   (`pyproject.toml` + Cython 3 + setuptools/scikit-build-core) so `qiradb` is built as a wheel in
   Docker and CI. Fix compile errors on current GCC/Clang (C++17 flag, `std::unordered_map` with a
   hash for `pair<Address,char>` instead of the `__cplusplus == 201103L` check, Python 3 `str`/`bytes`
   in `qiradb.pyx`).
2. **Read `meta.json`:** the Python wrapper in `src/qira/core/db.py` takes register size/count and
   endianness from `meta.json` instead of constructor arguments derived from `arch.py`.
3. **Conformance suite** (`qiradb/tests/`): pytest tests on the golden logs and on small synthetic
   logs written with `core/log.py`, covering `get_maxclnum`/`get_minclnum`, `did_update` while a log
   is growing, `get_pmaps`, `fetch_registers`, `fetch_memory` (valid mask), `fetch_changes_by_clnum`,
   `fetch_clnums_by_address_and_type` (limits, ranges). Plus a simple benchmark script.
   This suite is the contract that any later backend (TODO C++ modernization, Stage 4 Rust) must pass.

**Done when:** the wheel builds in Docker/CI on Python 3.12+ and the conformance suite passes.

### 1D. Python core package (`src/qira/core`)

| Legacy | New | Notes |
|---|---|---|
| `middleware/arch.py` | `core/arch.py` | Arch descriptors as frozen dataclasses/pydantic models (`name`, `register_names`, `register_size`, `big_endian`, `call_mnemonics`, `qemu_target`, `capstone_mode`). Remove list mutation such as `arch.MIPSREGS[2:-1] = …`. |
| `qira_program.identify_program` | `core/binary.py` | Detect ELF / PE / Mach-O with pyelftools + LIEF; return a `BinaryInfo` model. |
| `qira_program.Program` / `Trace` | `core/program.py`, `core/trace.py` | No global `/tmp/qira_binary` symlink; no threads started from constructors; explicit `TraceStore(path)`. |
| `qira_program.execqira`, `qira_socat` | `core/tracers/{base,qemu_plugin,wine,pin}.py` | `TracerBackend` interface (`build_command`, `start`, `fork_at`); driven by `asyncio.create_subprocess_exec`, not `os.fork`. PIN is kept as an optional legacy backend. |
| `qira_log.py` | `core/log.py` | Reader/writer for change logs + `meta.json` + `_mods`; fixes the Python 2 `write_log`. |
| `qira_analysis.py` | `core/analysis.py` | Port to Python 3; pure functions over a trace; keep `get_instruction_flow`, `get_hacked_depth_map`, `analyse_calls`, `get_vtimeline_picture`, `slice`. |
| `static2/` | `core/static/` | Port to Python 3, capstone 5, current pyelftools; replace pickle cache with JSON/SQLite under the configured cache dir. |
| `qira_config.py` | `qira/config.py` (stub) | Plain settings object passed in; filled by pydantic-settings in Stage 2. |
| — | `core/models.py` | pydantic models shared with the API: `Change`, `RegisterSnapshot`, `MemoryBlock`, `Syscall`, `PageMap`, `Instruction`, `TraceInfo`, `ArchInfo`, `BinaryInfo`, `TraceMeta`. |

Also add a minimal click entry point (`qira trace BINARY [ARGS]...`) so the core can be used without
the server.

**Done when:** `qira trace qira_tests/bin/loop` produces a trace and a Python REPL can open it with
`qira.core` and get registers, memory, instructions and strace; unit tests for arch detection,
analysis and static pass on the golden fixtures.

---

## 4. Stage 2 — Server (FastAPI)

**Goal:** a FastAPI service with a typed, versioned API, live streaming over WebSockets, and easy
Docker deployment. The legacy `web/` frontend is not ported to the new API.

### Configuration (`src/qira/config.py`)

`pydantic-settings` `BaseSettings`, env prefix `QIRA_`, `.env` file support, nested delimiter `__`:

```python
class TracerSettings(BaseModel):
    qemu_dir: Path = Path("/opt/qira/qemu/bin")
    plugin_path: Path = Path("/opt/qira/lib/libqira.so")
    wine_path: Path | None = None
    ld_prefix: Path | None = None          # replaces fetchlibs.sh / QEMU_LD_PREFIX
    trace_libraries: bool = False

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="QIRA_", env_file=".env", env_nested_delimiter="__")
    host: str = "127.0.0.1"
    port: int = 3002
    socat_port: int = 4000
    trace_dir: Path = Path("/var/lib/qira/traces")
    cache_dir: Path = Path("/var/lib/qira/cache")
    with_static: bool = False
    cors_origins: list[str] = []
    log_level: str = "INFO"
    tracer: TracerSettings = TracerSettings()
```

Ship `.env.example` (it exists since Task 1; extend it). Precedence: CLI options > environment >
`.env` > defaults. Keep the variable names already in use as aliases (assumption A3):
`QIRA_STATIC_CACHE_DIR` → `cache_dir`, `QIRA_TRACER_DIR` → `tracer.qemu_dir`/`plugin_path`,
`QIRA_LIBS_DIR` → `tracer.ld_prefix`; `QIRA_ASM_FILE` goes away with the per-run `<id>_asm`.

### CLI (`src/qira/cli/main.py`, click only)

```
qira run BINARY [ARGS]...   [-s/--server] [--gate-trace ADDR] [--trace-libraries]
                            [--static] [--no-run] [--keep-runs] [--host] [--port] [--socat-port]
qira serve                  # API + frontend only, open traces from the UI or API
qira trace BINARY [ARGS]... # Stage 1 command, no server
qira clean                  # replaces --flush-cache
qira config show            # print effective settings
```

`ipaddr` validation is replaced by pydantic types (`IPvAnyAddress`, port ranges).

### REST API (`/api/v1`, pydantic request/response models, OpenAPI at `/api/v1/openapi.json`)

| Endpoint | Replaces |
|---|---|
| `GET /health` | — |
| `GET /program`, `GET /arch` | `arch` push, program info |
| `POST /runs` (binary, args, options) | `qira run`, re-run from UI |
| `GET /traces` | `maxclnum` push (per fork) |
| `DELETE /traces/{fork}` | `deletefork` |
| `POST /traces/{fork}/fork` (`clnum`, `pending` mods) | `forkat` |
| `GET /traces/{fork}/registers?clnum=` | `getregisters` |
| `GET /traces/{fork}/memory?clnum=&address=&length=` | `getmemory` |
| `GET /traces/{fork}/instructions?clnum=&before=&after=` | `getinstructions` |
| `GET /traces/{fork}/clnums?address=&types=&limit=` | `getclnum` |
| `GET /traces/{fork}/changes?address=&type=&cview=&cscale=` | `getchanges` |
| `GET /traces/{fork}/navigate?clnum=&direction=` | `navigatefunction` |
| `GET /traces/{fork}/strace` | `strace` push (initial state) |
| `GET /traces/{fork}/slice?clnum=` | `doslice` |
| `POST /traces/{fork}/analysis` | `doanalysis` |
| `GET /traces/{fork}/timeline` | `setpicture` (initial state) |
| `GET /pmaps` | `pmaps` |
| `GET /static/names?addrs=`, `GET /static/goto?name=` | `getnames`, `gotoname` |
| `GET/POST /static/tags` | `gettagsa`, `gettagss`, `settags` |
| `GET /static/view?address=&flat=&range=`, `GET /static/function/{addr}`, `GET /static/graph/{addr}` | `getstaticview`, `/dot` |
| `POST /static/make` | `make` |
| `PUT /static/function/{addr}/args` | `setfunctionargswrap` |

Addresses are sent as hex strings in JSON (64-bit values do not fit in JS numbers).

### WebSocket (`/api/v1/ws`)

* Envelope `{"type": str, "payload": …}`, validated with a pydantic discriminated union on both sides.
* Client → server: `subscribe {forks}`, `unsubscribe`, `run.stdin {run_id, data}`.
* Server → client (streamed): `trace.added`, `trace.updated {fork, minclnum, maxclnum}`,
  `timeline.updated {fork, picture}`, `strace.append {fork, entries}`, `pmaps.updated`,
  `analysis.ready {fork}`, `run.stdout {run_id, data}`, `run.exited {run_id, code}`.
* A background `TraceWatcher` task (FastAPI lifespan) polls `did_update()` per trace and pushes
  deltas, replacing `mwpoll`/`mwpoller` and the gevent loop. Analysis runs in a worker thread pool
  per trace and is incremental where possible.
* Point lookups (registers, memory, instructions) stay on REST; only live data is streamed.

### Network services (`--server`)

`qira_socat.py` becomes an asyncio TCP server (`core/tracers/socat.py`): each connection starts a
traced run with stdio piped to the socket; the fork port starts fork-at-clnum runs. It is started by
`qira run --server` and configured with `QIRA_SOCAT_PORT`.

### Docker

* `docker/Dockerfile`, multi-stage:
  1. `qemu-build`: pinned upstream QEMU (`--enable-plugins`, `*-linux-user` targets) + `libqira.so`
  2. `qiradb-build`: qiradb wheel
  3. `frontend-build`: `npm ci && npm run build` (Stage 3; empty before then)
  4. `runtime`: `debian:trixie-slim` (or `ubuntu:24.04`), Python 3.12+, the wheels, QEMU binaries,
     frontend assets; `ARG WITH_WINE=0` adds Wine (i386 + amd64).
* `docker-compose.yml`: `qira` service, port 3002 (+4000/4001), volume for `QIRA_TRACE_DIR`,
  `env_file: .env`, a bind mount for binaries to trace, healthcheck on `/api/v1/health`.
* Runs as a non-root user.

### Tests

pytest + `httpx.AsyncClient` against the app with the golden traces; WebSocket tests with
`starlette.testclient`; a test that runs `qira run qira_tests/bin/loop` in the container and checks
`/api/v1/traces`. `run_tests.sh` and nose are removed.

**Done when:** `docker compose up` serves the API; `qira run qira_tests/bin/loop` in the container
creates a trace; every legacy Socket.IO event has a working REST/WS replacement; the OpenAPI spec is
published and covered by tests.

---

## 5. Stage 3 — Frontend (React)

**Goal:** a simple, fast, intuitive UI on top of the v1 API.

### Stack

* `frontend/`: Vite + React + TypeScript (strict).
* Types generated from the OpenAPI spec with `openapi-typescript` (`npm run gen:api`), plus a small
  typed fetch client.
* TanStack Query for REST data and caching; Zustand for the shared selection state
  (`forknum`, `clnum`, `iaddr`, `daddr`, `cview`).
* `useQiraSocket` hook: one WebSocket per tab with reconnect; streamed messages update the Query
  cache and the store.

### Layout (fixed, resizable panels — no docking framework)

```
+---------+-----------------------------------------+------------------+
|         | Controls: [clnum] [fork] [iaddr] [daddr]| Registers        |
| Time-   +-----------------------------------------+------------------+
| line    | Instructions (idump)  | Static / Graph  | Memory (hexdump) |
| (canvas,|                       |   (tab)         +------------------+
|  forks) |                       |                 | Data changes     |
|         +-----------------------------------------+------------------+
|         | Run console (xterm.js, stdin/stdout)    | Strace           |
+---------+-----------------------------------------+------------------+
```

* `react-resizable-panels`; layout saved in localStorage.
* Same colour semantics as today: blue = clnum, grey = fork, red = iaddr, yellow = daddr
  (bright yellow write, dark yellow read).
* Keyboard shortcuts from `web/client/controls.js` and the mouse actions in README are kept;
  fork creation/deletion move into a context menu on the timeline.
* Run panel: start or re-run the binary with arguments; program I/O over the WebSocket.
* Light/dark theme follows the OS.

### Live data

Streamed over the WebSocket: trace growth (`maxclnum`), timeline picture, strace, pmaps, analysis
status, run stdout. Everything else is fetched over REST on selection change.

### Serving and tests

* Production build served by FastAPI `StaticFiles` at `/`; Vite dev server proxies `/api` and the WebSocket.
* Vitest for components and hooks; Playwright smoke test against the Docker image: open the app,
  see the `loop` trace, step clnum with the keyboard, and check that registers and memory update.

**Done when:** the Playwright smoke test passes in CI against the Docker image; `web/`,
`middleware/`, `static2/` and the other legacy items listed in §1 are removed.

---

## 6. Stage 4 — qiradb rewrite in Rust

**Goal:** a memory-safe, faster trace database with the same Python API.

* `qiradb-rs/`: PyO3 + maturin, `memmap2` for the log, `parking_lot::RwLock`, a background ingest
  thread that follows the growing log.
* Memory history stored per page with sorted `(clnum, value)` runs instead of per-byte maps.
* Same Python API as the current `PyTrace` (names and return types), so `core/db.py` can switch
  backends with `QIRA_DB_BACKEND=cpp|rust`.
* **Acceptance:** passes the Stage 1C conformance suite and matches or beats the recorded benchmarks
  (ingest speed, query latency, peak RSS). After that, the Rust backend becomes the default and the
  C++ backend is removed.

---

## 7. Stage 5 — Windows, part 2: native DynamoRIO tracer

**Goal:** faithful tracing of Windows binaries that do not work under Wine.

* `tracers/dynamorio/`: a DynamoRIO client built with CMake/MSVC on Windows (CI: GitHub Actions
  `windows-latest`).
* Emits the same change records, `meta.json` (`tracer: "dynamorio"`, `os: "windows"`), `_strace`
  (NT syscalls by name), `_base` and `_images` (already supported by `load_base_memory`).
* Two delivery modes: write a trace bundle that is uploaded via `POST /api/v1/traces/import`, or
  stream it live over a `/api/v1/ingest` WebSocket to a QIRA server on another host.
* Fixtures: `tests_manual/windows/*.exe`, compared with the Wine traces from Stage 1B where both work.

---

## 8. Verification checklist per stage

| Stage | Commands / checks |
|---|---|
| 0 | `uv run pytest` runs; golden fixtures present under `tests/fixtures/golden/`; CI green |
| 1 | `docker build --target qemu-build .`; `uv run qira trace qira_tests/bin/loop`; `uv run pytest tests/core qiradb/tests`; golden comparison tests pass; Wine spike result recorded; `qira trace tests_manual/windows/fibonacci64.exe` (if go) |
| 2 | `docker compose up -d`; `curl localhost:3002/api/v1/health`; `docker compose exec qira qira run qira_tests/bin/loop`; `curl localhost:3002/api/v1/traces`; `uv run pytest tests/server` (REST + WS) |
| 3 | `npm --prefix frontend run test`; `npx playwright test` against the compose stack; manual check in a browser |
| 4 | `QIRA_DB_BACKEND=rust uv run pytest qiradb/tests`; benchmark report vs. C++ |
| 5 | Windows CI builds the client; imported DynamoRIO trace of `fibonacci64.exe` opens in the UI |
