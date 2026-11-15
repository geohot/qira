# Task 5 — Minimal QEMU plugin tracer (x86_64)

Branch: `feature/qemu-plugin-tracer` · Date: 2026-11-15

Replaces the broken QEMU 2.5.1 fork with a TCG plugin loaded into upstream QEMU 11.1.x
(plugin API 7), as decided in [docs/tracer-assessment.md](../tracer-assessment.md). `./qira`
traces x86_64 Linux binaries live again; the legacy middleware and web UI are unchanged.

## What was done

* **`tracers/qemu-plugin/qira.c`** (+ `Makefile`): `libqira.so`, a QEMU TCG plugin that writes
  QIRA's legacy trace format so the existing middleware and `qiradb` read it unchanged:
  * `<dir>/<run>` — the 24-byte change log, with records:
    * `I` (instruction start, pc + size) for main-binary instructions (all code with `tracelibs=on`);
    * `L`/`S` (load/store, value + size) from all code, via `qemu_plugin_register_vcpu_mem_cb` +
      `qemu_plugin_mem_get_value`;
    * `W` (register write) by reading the 17 `arch.X64REGS` registers at each instruction boundary
      and emitting the ones that changed, mapped from the plugin's gdb names (`rax`→index 0, …,
      `rip`→16) to `address = index * 8`.
  * `<dir>/<run>_strace` — `"<clnum> <pid> name(args) = ret"`. `openat`/`open` and `mmap` are
    formatted exactly as `read_strace_file` parses them (quoted path; fd and offset as integers),
    so the middleware loads mmap'd library memory from the real host files. Other syscalls are
    written generically (`syscall_<n>(...)`).
  * `<dir>/<run>_base` — the main binary's `PT_LOAD` segments from its ELF program headers
    (`<vaddr>-<vaddr+filesz> <file_offset> <host_path>`). Libraries are covered by the `_strace`
    mmap lines instead (the middleware maps them from there).
  * `<asm>` — `qemu_plugin_insn_disas` lines; empty on nixpkgs `qemu-user` (built without capstone),
    which is fine: `static2`/capstone disassembles from the bytes `_base` loads.
  * Plugin arguments: `dir=`, `run=`, `asm=`, `tracelibs=on`, `gate=0x…`. The plugin writes straight
    to the configured trace dir and asm file, which **fixes issue I1** (the legacy tracer hardcoded
    `/tmp/qira_logs` and `/tmp/qira_asm`).
* **Middleware** (`qira_program.py`, `qira_config.py`): `QIRA_QEMU_PLUGIN` (default
  `TRACER_DIR/qemu-plugin/libqira.so`). For an x86_64 ELF, when the plugin and an upstream
  `qemu-x86_64` (in `TRACER_DIR/qemu/` or on `PATH`, which the devenv shell provides) are both
  present, `Program` sets `use_plugin` and `execqira` runs
  `qemu-x86_64 -plugin <libqira.so>,dir=…,run=…,asm=…[,tracelibs=on] <binary> <args>`. Other
  architectures keep the legacy `qira-<arch>` path (still broken, I2). `--server`/socat and
  `forkat` raise `NotImplementedError("fork/replay not supported by the plugin tracer yet")`,
  caught by the existing handlers.
* **devenv**: `qemu-user`, `glib.dev`, `pkg-config` and `QEMU_PLUGIN_INCLUDE` were added in the
  first commit of this branch (the user entered the shell once: QEMU 11.1.2, plugin API 7).
* The Task 3 **spike** (`tracers/qemu-plugin/spike/`) was deleted; `qira.c` supersedes it.

## How it was verified

In the devenv shell (`make -C tracers/qemu-plugin`, `qemu-x86_64` on PATH):

* **Live trace**: `./qira --web-port 3012 qira_tests/bin/loop` runs the plugin, which writes the
  trace; the middleware serves it. `qira_tests/smoke_socketio.py` PASSES (maxclnum `{'0': [0,149]}`,
  17 registers, instructions disassembled, memory bytes).
* **Instruction sequence**: the plugin's `(clnum, pc, size)` for `loop` equals `samples/legacy/0`
  for **all 149 instructions**.
* **Web UI** (`qira_tests/ui_check.py`, headless Firefox): on a live plugin trace, idump
  (disassembly via static2), registers, strace and the timeline all populate.
* **Tests**: `uv run pytest` → 42 passed, 1 skipped. New `qira_tests/test_plugin_tracer.py`
  (trace files, I-sequence vs legacy, middleware round-trip) and an updated
  `qira_tests/test_qira_program_runs.py` run live; both skip cleanly without `qemu-x86_64` or the
  built plugin.
* **Throughput**: ~**324k instructions/s**, ~1.4M records/s, about **4.3× slower** than bare
  `qemu-x86_64` (tracing `ls /usr/include`: 240k instructions, 25 MB log, 0.74 s).

## Differences from the legacy trace (remaining)

Record counts for `qira_tests/bin/loop`:

| | plugin | legacy |
|---|-------:|-------:|
| I (instructions) | 149 | 149 |
| S (stores)       | 12 489 | 12 330 |
| L (loads)        | 28 446 | 35 033 |
| W (reg writes)   | 213 | 579 |
| R (reg reads)    | 0 | 186 |

* **No `R` (register read) records.** The plugin API reports register *values*, not which
  registers an instruction read. Effect: the UI's `regread` highlight is absent; register *values*
  are correct. Stage 1A can derive `R` from capstone (`regs_access`).
* **Fewer `W` records** (213 vs 579): the plugin emits a register write only when the value
  changes, and only for the 17 `X64REGS` (not flags/segment registers). Register *values*
  reconstruct correctly (the last write wins); only the per-clnum "written here" highlight shows
  fewer registers.
* **Fewer `L` records** (28 446 vs 35 033): the legacy TCI hooked loads at the micro-op level and
  also recorded kernel reads; the plugin records guest load instructions only. Memory *values* are
  still correct from stores and static memory.
* **No kernel-write records yet.** The legacy tracer recorded bytes the kernel writes into guest
  memory during syscalls (e.g. `read`, `fstat`) as 1-byte `S` records. Not implemented; the hook
  point (`qemu_plugin_register_vcpu_syscall_ret_cb` + `qemu_plugin_read_memory_vaddr`) is in place.
* **strace** names only `open`/`openat`/`mmap`; other syscalls are `syscall_<n>(a,b,c)`. Enough for
  the middleware's static-memory loading; a full name/format table is Stage 1A.
* **No `_env` file / stack-region `_base` line.** The legacy tracer dumped the initial stack/env.
  Not needed for the UI; the env panel is empty.

## Not done (later tasks)

* Fork-at-clnum (`forkat`) and `--server`/socat replay (Stage 1A: deterministic re-run with the
  syscall filter; raises `NotImplementedError` for now).
* Other architectures (i386, arm, aarch64, mips, ppc) — still the legacy path (I2). Stage 1A.
* `meta.json` sidecar, `R` records, kernel writes, full strace, per-run `<id>_asm` — Stage 1A.

## For the next tasks

* Build the plugin: `make -C tracers/qemu-plugin` in the devenv shell (needs `QEMU_PLUGIN_INCLUDE`
  and glib; both are in the shell). `libqira.so` is git-ignored (`*.so`).
* **Task 2** can now capture with the plugin: `QIRA_TRACE_DIR=samples/port ./qira --web-port 3012
  qira_tests/bin/loop` writes `samples/port/0` etc. The podman copy of the legacy binary is only
  needed to separate libc differences from tracer differences.
* **Task 4** installs upstream QEMU 11.1.x + this plugin into
  `${XDG_DATA_HOME:-~/.local/share}/qira/tracers/qemu/` (see the assessment).
* The nixpkgs `qemu-user` has no capstone, so `qemu_plugin_insn_disas` is empty and the plugin
  writes no asm; the middleware's own capstone covers disassembly. A source-built QEMU with
  capstone would populate the asm file.
