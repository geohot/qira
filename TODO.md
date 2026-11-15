# QIRA TODO — optional improvements

These items are **not required** for the upgrade described in [UPGRADE.md](UPGRADE.md). Each one would
improve or extend QIRA once the relevant stage is done. The "After" column names the earliest stage
the item can start from.

## qiradb C++ modernization (moved out of UPGRADE.md Stage 1C)

After: Stage 1. UPGRADE.md Stage 1C only makes the existing C++/Cython qiradb build on modern Python
and adds the conformance suite. This item is the full modernization, done before or instead of the
Stage 4 Rust rewrite.

- [ ] C++20: `std::shared_mutex` for the DB lock, `std::jthread` for the ingest thread, and remove
      the pthread/Win32 macro layer in `Trace.h` (keep only cross-platform file mapping).
- [ ] Compact memory history: page-level store with sorted `(clnum, value)` vectors instead of a
      `std::map<Clnum, uint8_t>` per byte (`memory_` in `Trace.h`). Same for `registers_`.
- [ ] Replace Cython with **nanobind** bindings; release the GIL in all fetch calls.
- [ ] `fetch_memory` returns `bytes` plus a validity mask (or a numpy view) instead of a list of
      `uint16` with the `0x100` valid bit.
- [ ] Package with scikit-build-core as a proper wheel (Linux x86_64/aarch64, Windows, macOS).
- [ ] Keep the Python API names (`fetch_registers`, `fetch_memory`, `fetch_changes_by_clnum`,
      `fetch_clnums_by_address_and_type`, `get_pmaps`, `get_maxclnum`, `get_minclnum`, `did_update`).
- [ ] Must pass the Stage 1C conformance suite; record benchmarks (ingest speed, query latency, peak
      RSS) so Stage 4 has a baseline to compare against.
- [ ] C++ unit tests (Catch2 or GoogleTest) for the ingest thread on a growing log.

## AI assistance

After: Stage 3. Runs **from the frontend**, using an **OpenAI-compatible `/v1` API**
(`/v1/chat/completions` with streaming). Assumption: "openapi api v1 format" in the original request
means the OpenAI-style v1 API, so any compatible provider works (hosted models via a compatible
gateway, local Ollama / vLLM / llama.cpp server, etc.). The context is gathered from QIRA's own
`/api/v1` endpoints.

- [ ] **Settings panel:** base URL, model, API key, temperature, max context size. Stored in the
      browser (localStorage); never sent to the QIRA server unless proxy mode is on.
- [ ] **Explain code:** select an instruction range or a function in the instruction/static view →
      send the disassembly, names, comments and xrefs from `/api/v1/static/*`, plus register/memory
      state at the current clnum.
- [ ] **Explain execution history:** summarize a clnum range — which functions ran, syscalls, memory
      regions written, loops — and answer questions such as "where did this value come from?".
- [ ] **Context endpoint:** `GET /api/v1/traces/{fork}/context?start=&end=&address=` on the server
      builds a compact, token-bounded summary (instruction flow, call tree, syscalls, data writes,
      `slice` results), so prompts stay small and deterministic.
- [ ] **Improvement suggestions:** for a selected code section, suggest improvements and point out
      likely bugs (buffer overflows, use-after-free, unchecked syscall returns, integer issues),
      using data-flow from `slice` as evidence.
- [ ] **Chat side panel:** streamed responses (SSE from the provider), Markdown rendering, and
      clickable references to clnums, addresses and functions that navigate the UI.
- [ ] **Saved notes:** store useful answers as comments/tags in static (`/api/v1/static/tags`).
- [ ] **Optional server proxy mode:** `POST /api/v1/ai/chat` forwards to the configured provider
      (`QIRA_AI__BASE_URL`, `QIRA_AI__API_KEY`, `QIRA_AI__MODEL` via pydantic-settings), so keys stay
      on the server in shared/Docker deployments.
- [ ] **Optional tool calling:** expose QIRA queries (registers, memory, instructions, strace, slice)
      as tools so the model can explore the trace itself.
- [ ] Privacy note in the UI: code and trace data are sent to the configured provider.

## Debugger and tool integration

- [ ] GDB remote serial protocol stub over a trace (After: 2): `stepi`/`reverse-stepi`,
      `continue`/`reverse-continue` to breakpoints and watchpoints, read registers/memory at any clnum.
- [ ] Ghidra extension and Binary Ninja plugin that sync the current address/clnum with QIRA over
      the v1 WebSocket (After: 2).
- [ ] IDA 9 Python plugin that replaces the prebuilt binaries in `ida/` (After: 2).
- [ ] VS Code / editor integration that replaces `extra/vim/qira.vim` (After: 2).

## Symbols, types and source

- [ ] DWARF: function names, local variables and source-line view next to the instructions (After: 1).
- [ ] PDB loading for Windows binaries (via LIEF or `llvm-pdbutil`) (After: 1B).
- [ ] Demangling for C++/Rust symbols in all views (After: 1).
- [ ] Decompiler view (Ghidra headless or another decompiler) for the current function (After: 3).

## Trace storage and performance

- [ ] Persistent trace index (SQLite or Parquet) so large traces reopen instantly and can exceed
      RAM (After: 4).
- [ ] Trace compression (zstd blocks) and pruning/retention policies for `QIRA_TRACE_DIR` (After: 2).
- [ ] Incremental analysis instead of the full recompute in the analysis loop (After: 1D).
- [ ] WebGL/OffscreenCanvas timeline for very large traces (After: 3).
- [ ] Multi-threaded guest support (one log per thread, merged view) (After: 1A).

## Analysis features

- [ ] Search over time: "when did address X hold value Y", string search in memory history,
      "first write to range" (After: 2).
- [ ] Trace diffing between forks or between two runs with different input (After: 2).
- [ ] Taint tracking from syscall input buffers (`read`, `recv`) through the trace (After: 1).
- [ ] Heap visualization (malloc/free tracking) (After: 3).
- [ ] Export: trace bundle import/export (zip with log + sidecars + meta.json), and CSV/JSON export
      of selected ranges (After: 2).

## Platforms

- [ ] More architectures: riscv32/riscv64, loongarch64, s390x, sparc (After: 1A).
- [ ] macOS hosts: document Docker as the supported path; optional native PIN/DynamoRIO tracer.
- [ ] System-mode tracing (qemu-system + plugin filtered by process) for kernel or firmware work.

## Deployment, security and multi-user

- [ ] Authentication (OIDC or token) and per-user sessions for shared servers (After: 2).
- [ ] Projects / named runs that persist across server restarts (After: 2).
- [ ] Sandboxing of traced binaries in Docker (seccomp profile, no network by default, resource limits)
      (After: 2).
- [ ] Publish the Python package to PyPI and the Docker image to GHCR (After: 3).
- [ ] Documentation site (MkDocs) with tutorials and the API reference generated from OpenAPI (After: 2).

## UX

- [ ] Accessibility pass (keyboard-only use, screen-reader labels, colour-blind safe palette) (After: 3).
- [ ] Shortcut help overlay (`?`) and a command palette (After: 3).
- [ ] Bookmarks for clnums/addresses with notes (After: 3).
