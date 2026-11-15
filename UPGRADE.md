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

---

## 1. Current-state assessment

### Components

| Component | Location | State |
|-----------|----------|-------|
| Tracer | `tracers/qemu_build.sh` → `geohot/qemu@qira`; patches in `extra/qemu_mods/{tci.c,main.c,strace.c,disas.c}` | QEMU 2.x fork using the TCG interpreter (TCI). Does not build on modern toolchains (README notes 18.04 already fails). Prebuilt `tracers/qemu/qira-*` binaries are stale. |
| Alternative tracer | `tracers/pin/qirapin.cpp`, `tracers/pin_build.sh` | Intel PIN tool, used on macOS / optional on Linux. Tied to an old PIN release. |
| Trace database | `middleware/qiradb/` (`Trace/Trace.{h,cpp}`, `qiradb.pyx`, `qiradb.pyxbld`) | C++ reader of the mmap'd change log, built on the fly via `pyximport`. Uses a `#define unordered_map map` fallback unless `__cplusplus == 201103L` exactly (so it is a `std::map` on any modern compiler). Memory history is a `std::map<Clnum,uint8_t>` **per byte**, which uses a lot of RAM. |
| Middleware | `middleware/*.py` | Mixed Python 2/3 (`#!/usr/bin/env python2.7`, `__future__`, `urllib.unquote`, `str`/`bytes` mix). Flask 1.0 + Flask-SocketIO 3 + gevent. argparse CLI. Process control via `os.fork`/`os.execvp`. Global mutable config in `qira_config.py` with hardcoded `/tmp` paths. |
| Static analysis | `static2/` | Python 2 era. capstone 4, pyelftools 0.25. Pickle-based cache in `/tmp/qira_static_cache/`. |
| Frontend | `web/` | jQuery 2, a Meteor shim (`fakemeteor.js`), wcDocker, socket.io client 1.x. |
| Dependencies | `requirements.txt` | Pinned 2019 versions (Flask 1.0.2, Cython 0.29.6, nose, ipaddr, socketIO-client…). |
| Install / CI | `install.sh`, `docker/Dockerfile` (ubuntu:16.04), `.travis.yml`, `run_tests.sh` (nose) | Installs `python` (2), builds QEMU. Travis is dead. |

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
`install.sh` (replaced by Docker + `uv`), `requirements.txt`, `web/`, `middleware/`, `static2/`
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

1. **Golden traces.** Build the legacy image (`docker/Dockerfile`, ubuntu:16.04, with the old
   QEMU fork) and capture reference traces for `qira_tests/bin/loop`, `qira_tests/bin/hello_trace`
   and a selection of `tests_auto/source-autogen/*.c` (loop, forktest, heaptest, test64, echo).
   Store them in `tests/fixtures/golden/<name>/` with the log, `_strace`, `_base` and asm.
   Also export query results (registers/memory at selected clnums) as JSON, so later stages can
   compare without the old code.
2. **Packaging.** Add `pyproject.toml` (Python ≥ 3.12, managed with `uv`), with ruff, mypy, pytest
   and pre-commit. Add a GitHub Actions workflow (lint, test, Docker build) to replace Travis.
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

1. **Build on modern Python:** replace `pyximport` / `qiradb.pyxbld` with a proper build
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

Ship `.env.example`. Precedence: CLI options > environment > `.env` > defaults.

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
