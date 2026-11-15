# Task 1: Port `middleware/` to Python 3 (+ uv packaging)

Branch `feature/py3-middleware`, off `develop` (`862c3aa`).

## Change to the task as written

The task asked for `./venv` + a refreshed `requirements.txt`. On request, QIRA is now a **uv
project** that also installs as a **tool**:

* `pyproject.toml` (setuptools + Cython 3), `uv.lock`, `setup.py` (only the qiradb extension).
  `requirements.txt` is removed.
* The legacy code stays where it is and is installed as the package `qira`:
  `middleware/` → `qira`, `static2/` → `qira.static2`, `web/` → `qira.web` (data only).
  Console script `qira = qira.qira:main`; `python -m qira` works as well.
* `uv sync` gives an editable install in `.venv/`. `uv tool install .` gives a standalone
  `qira` command; the wheel contains the compiled qiradb, the web UI and static2.
* qiradb is compiled at install time by `setup.py` instead of `pyximport` (Stage 1C step 1
  done early). `[tool.uv] cache-keys` makes `uv sync` rebuild it when the `.pyx/.pxd/.cpp/.h`
  files change.
* `./qira` runs `.venv/bin/qira` and falls back to `uv run`.

UPGRADE.md (rules 4 and 8, Task 1, Task 2 step 2, Task 4, §1), CLAUDE.md and README.md are
updated to match.

## What was done

| Area | Change |
|---|---|
| Dependencies | flask 3.1, flask-socketio 5.7 (+ simple-websocket), capstone 5.0.9, pyelftools 0.33, pillow 13. Dev group: pytest 9, python-socketio[client] 5. Dropped: gevent/greenlet, ipaddr (→ `ipaddress`), nose, socketIO-client, six, requests/certifi/chardet/idna/urllib3 (runtime), hexdump and click (unused), pydot (only used by dead code in `draw_multigraph`). |
| qiradb | `Trace.h`: `std::unordered_map` with a hash for the `(address, type)` key on every compiler (it was a `std::map` because of the `__cplusplus == 201103L` check). The destructor only joins a thread that was started (it joined an uninitialised handle when the file could not be opened). printf formats are 64-bit clean, and the file size check no longer truncates to 32 bits. `qiradb.pyx`: Cython 3, `IOError` instead of `assert` on open failure, str or bytes accepted for path and type. Compiled with `-std=c++17 -O2`. |
| Python 3 | Relative package imports instead of `sys.path` hacks. `which()` returned **bytes** under Python 3 (it parsed `which` output), now `shutil.which`. bytes literals for the ELF/ARM checks. `fetch_raw_memory` returns bytes (it fed `str` to capstone/struct). `_strace` is read as bytes and filtered to ASCII. Web files are served as bytes (fonts and favicon would have failed). `qira_log.write_log` writes bytes. `/` → `//` in the timeline picture (PIL needs ints) and the call analysis. `urllib.parse.unquote`. `iter_keys()` (a bug in Python 2 as well) → `keys()`. `x86` imported explicitly in `model.py`. |
| Socket.IO | Flask-SocketIO 5, **`async_mode="threading"`** with Werkzeug + simple-websocket. gevent was not monkey-patched in the legacy code, so the analysis threads, the poller and qiradb were real threads anyway; threading mode makes that explicit and needs no extra dependency. The connect handler accepts Flask-SocketIO 5's `auth` argument (the `socket_method` wrapper would have dropped the call, so no state was pushed on connect). Shared dicts (`program.traces`, `static.base_memory`) are iterated over snapshots because the threads now run truly in parallel. |
| Browser client | `web/client/compatibility/socket.io.min.js` 1.x → **4.8.4** (npm tarball, integrity hash checked). `io.connect()` still exists; no other `web/` change. |
| Config | Environment overrides, defaults unchanged: `QIRA_TRACE_DIR` (`/tmp/qira_logs/`), `QIRA_STATIC_CACHE_DIR` (`/tmp/qira_static_cache/`), `QIRA_ASM_FILE` (`/tmp/qira_asm`), plus `QIRA_TRACER_DIR` (`<checkout>/tracers/`) and `QIRA_LIBS_DIR` (`<checkout>/libs/`), which the tool install needs. |
| Small behaviour changes | Background threads are daemons, so Ctrl-C ends the server. A web path containing `..` returns 404 instead of raising (it was a 500 before). `write_log`'s header `change_count` includes the header entry, as the tracer writes it (the tracer ignores it for `_mods`; qiradb needs it). "make string" names use ASCII alnum only, as in Python 2. |

## How it was verified

All checks ran on Debian 13, Python 3.13.5, GCC 14.2, uv 0.13.8.

* **Fresh clone** (`git clone -b feature/py3-middleware . $TMPDIR/qira-fresh`):
  `uv sync --locked` OK. `uv run pytest`: **18 passed, 2 skipped** (the tracer test, and the
  legacy capture test because `samples/` is not in git). In the working checkout with `samples/`:
  **19 passed, 1 skipped**.
* `uv run python -m compileall -q middleware static2` prints nothing.
* **Wheel / tool:** `uv build --wheel` contains `qira/qiradb/qiradb.cpython-313-x86_64-linux-gnu.so`,
  32 files under `qira/web/` (fonts included) and `qira/static2/`. After `uv tool install .`,
  `qira --help` works and `WEB_DIR` resolves inside site-packages.
* **Tests** (`qira_tests/`):
  * `test_qiradb.py`: the original `hello_trace` assertions plus registers/changes/pmaps; a
    synthetic x86-64 log (registers, little-endian memory, invalid bytes, pmaps); the open-failure
    path; `samples/legacy/0` cross-checked against a plain Python read (min/max clnum, changes of
    one clnum).
  * `test_qira_log.py`: write/read round trip, header count, stop at an invalid entry, `flag_to_type`.
  * `test_qira_program.py`: `which`, ELF/PE identification, `_strace` parsing (incl. non-ASCII
    and missing file), mmap → static memory, `_base` parsing, register/memory proxies, env overrides.
  * `test_static2.py`: the loop binary's arch, entry, `main`, functions, disassembly, jump dests, memory.
  * `test_webserver.py`: `/`, binary files, JS wrapping, `..`; Socket.IO test client: the push on
    connect (`maxclnum`, `arch`, `pmaps`, `strace`) and `getregisters`, `getmemory`,
    `getinstructions`, `getclnum`, `getchanges`, `getnames`.
  * `test_qira_program_runs.py`: skipped, reason "QEMU tracer … does not resolve".
* **Smoke test (step 6)**, server and client in one command (see below for why):

  ```
  cp -r samples/legacy $TMPDIR/legacy-copy
  QIRA_TRACE_DIR=$TMPDIR/legacy-copy QIRA_ASM_FILE=$TMPDIR/qira_asm \
    ./qira --no-run --no-delete-runs --host 127.0.0.1 --web-port 3012 --socat-port 4010 qira_tests/bin/loop &
  curl -s localhost:3012/ | grep '<title>qira</title>'      ->  <title>qira</title>
  uv run python qira_tests/smoke_socketio.py --url http://127.0.0.1:3012
    connected to http://127.0.0.1:3012 (transport websocket)
    maxclnum: {'0': [0, 149]}
    arch: x86-64, 17 registers of 8 bytes
    clnum      0: 17 regs, pc 0x400440, RSP=0x4000800d70, 3 instructions (0x400445 pop rsi), 24/32 memory bytes
    clnum      1: 17 regs, pc 0x400442, RSP=0x4000800d70, 3 instructions (0x400445 pop rsi), 24/32 memory bytes
    clnum     74: 17 regs, pc 0x40053a, RSP=0x4000800c90, 5 instructions (0x400537 mov rbp, rsp), 32/32 memory bytes
    clnum    148: 17 regs, pc 0x4005ec, RSP=0x4000800b98, 4 instructions (0x4005e8 add rsp, 8), 32/32 memory bytes
    PASS
  ```

  The server was stopped afterwards (trap on exit).
  **`--no-run` does load existing traces**: `mwpoll` adds every numbered file in the trace
  folder, the same as the legacy code. The legacy `_base` names paths inside the container
  (`/qira/qira_tests/bin/loop`, Ubuntu 16.04 libs, `/tmp/qira_logs/0_env`), so those
  regions are reported as "Failed to get …" and not loaded. That is expected and is a Task 2
  topic.

## Not verified

* The UI in a real browser (the socket.io 4 client is only exercised by the Python client and
  the Flask-SocketIO test client).
* Tracing a live binary: there is no tracer on this host (`tracers/qemu/qira-*` are broken symlinks).
  `forkat`, `--server`/socat and the PIN path were not run.
* `-S`/`--static` (static analysis threads, `getstaticview`, `make`) is only covered by `test_static2.py`.
* `static2/testing.py` / `run_tests_static.sh` (needs `tests_auto/binary-autogen`, which is not built;
  `tests_auto/autogen.py` was not ported, but it parses under Python 3).
* `run_tests.sh`'s integration part (needs the tracer).

## Findings and open questions

1. **The tracer paths are hardcoded.** `extra/qemu_mods/tci.c` writes `/tmp/qira_logs/<id>…` and
   `/tmp/qira_asm`, and `qirapin.cpp` writes `/tmp/qira_logs`. `QIRA_TRACE_DIR`/`QIRA_ASM_FILE`
   only change where the middleware reads, so Task 2 step 2 ("capture into `samples/port`")
   cannot work as written. UPGRADE.md Task 2 is updated with the alternatives.
2. **Sandbox limits for later tasks.** Claude's sandbox cannot write `/tmp` outside `$TMPDIR`, and
   each command runs in its own network namespace (a server started in one command is not
   reachable from the next). Live captures (Task 2) therefore need you to run them, or the sandbox
   has to allow `/tmp/qira_logs` and `/tmp/qira_asm`.
   **Follow-up:** the sandbox is to allow both paths. They are bind mounts there, so
   `delete_old_runs()` now empties the trace folder and `create_asm_file()` truncates the asm file
   instead of deleting them.
3. **`uv` is not installed on the host.** For this task it ran from `$TMPDIR/uvenv`. Please install
   it (e.g. `curl -LsSf https://astral.sh/uv/install.sh | sh`, which goes to `~/.local/bin`; or
   `pipx install uv`).
   **Follow-up:** uv now comes from a devenv shell (`devenv.nix`, entered via direnv `.envrc`),
   and the `QIRA_*` settings from `.env` (template `.env.example`). Nix, devenv and direnv have to
   be installed by the user (Nix needs sudo).
4. **Tool install and the tracer.** The installed package does not contain the QEMU tracer. Set
   `QIRA_TRACER_DIR` to the checkout's `tracers/`. Task 3/4 should decide where an installed
   tracer lives (e.g. `~/.local/share/qira`) and make that the default.
5. **The legacy Docker image.** `docker/Dockerfile` and `install.sh` still use `requirements.txt` and
   Python 2. Rebuild `qira-legacy` from a commit before this branch (e.g. `862c3aa`).
6. **The package name.** The legacy modules are now importable as `qira.*` (e.g. `qira.qira_program`).
   Stage 0/1D plans `src/qira/core/…`; when that starts, the legacy mapping should move to
   e.g. `qira.legacy` or be replaced as modules land.
7. **Legacy bugs left as they are** (not Python 3 related): the `doanalysis` handler calls
   `get_vtimeline_picture` with too few arguments (the error is logged); `qira.py` swallows the
   "can't run as server if QIRA is already running" exception in a bare `except`;
   `--flush-cache` runs `rm -rfv /tmp/qira*`; `os.fork()` is used from a threaded process
   (Python 3.12+ may warn; Stage 2 replaces it with subprocesses).
8. **The legacy `/tmp/qira_binary` symlink** is still created (and silently skipped when `/tmp` is not
   writable).

## For the next tasks

* Run everything through uv: `uv sync`, `uv run pytest`, `uv run qira …` or `./qira`.
* `qira_tests/smoke_socketio.py` checks a running server end to end. `conftest.py` has a synthetic
  x86-64 log and `_strace`/`_base` fixtures that Task 2 and Stage 1C can reuse.
* In the sandbox, start the server and its client in the **same** command, with a `trap` that
  kills the server.
