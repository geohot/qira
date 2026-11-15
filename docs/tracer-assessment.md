# QEMU tracer assessment (Task 3)

Date: 2026-11-15 · Branch: `feature/tracer-assessment` · Host: devserver-01 (Debian 13, x86_64)

## Recommendation

**Replace the tracer with a QEMU TCG plugin** (`libqira.so`, §3 1A of UPGRADE.md) loaded into
unmodified upstream QEMU, **pinned to QEMU 11.1.x** (plugin API version 7). Do not rebase the
qira patches.

* For development, the QEMU comes from **nixpkgs `qemu-user`** (QEMU 11.1.2 with plugins at the
  `devenv.lock` pin), added to `devenv.nix`. No sudo, no QEMU build.
* For the user install (`install.sh`, Task 4) and Docker, **build upstream QEMU 11.1.x
  `*-linux-user --enable-plugins` from source**. Debian 13's own `qemu-user` cannot load plugins
  (static build), so it is not an option.
* The spike shows the approach works: a ~150-line plugin, loaded into a stock QEMU 11.1.3, gives
  **the same instruction sequence (clnum, pc, size) as the legacy tracer for all 149 instructions**
  of `qira_tests/bin/loop`.

Effort for a plugin with the legacy tracer's x86_64 feature set, without fork/replay: about
**1.5–2 weeks**. Fork/replay adds about **1 week** (higher risk). Each further architecture adds about
**1–2 days**. A rebase of the qira patches would be about **3–5 weeks** first, then work on every
QEMU release, on an interpreter (TCI) that no distribution ships.

## 1. Size of the qira delta

`geohot/qemu@qira` is **QEMU v2.5.1** (March 2016) plus two commits by George Hotz (2019-03-24,
"qira qemu patches from upstream", "make qira patches build without warnings").
`git diff v2.5.1 qira`: **10 files, +780 / −34 lines**, 672 of them in `tci.c`.

| Feature | Where | Size |
|---|---|---|
| Change log: buffer, `logstate` header, `add_change`, pending changes, `init_QIRA` (opens `/tmp/qira_logs/<id>`, `_strace`, `_base`) | `tci.c` | ~130 lines |
| Tracing hooks in the interpreter: `track_load`/`track_store` (guest memory), `track_read`/`track_write` (any `CPUArchState` field by offset) in the TCI load/store op handlers | `tci.c` | ~40 lines of hooks in op handlers + ~20 lines of helpers |
| Instruction start (`I` record per TB; QEMU runs with `-singlestep`, so a TB is one instruction), per-arch syscall detection (i386, x86_64, ARM, MIPS) | `tci.c` (TB entry) | ~120 lines |
| Kernel reads/writes into guest memory (`lock_user`/`unlock_user` → 1-byte `S`/`L` records) | `linux-user/qemu.h`, `tci.c` | ~45 lines |
| strace into `<id>_strace` (redirected `gemu_log`, 64-bit format fixes) | `linux-user/strace.c`, `strace.list` | ~30 lines |
| Fork/replay: `-qirachild "parent clnum id"`, `run_QIRA_log*` replays the parent's **writes** (memory and `CPUArchState` bytes) up to `clnum`, then `<id>_mods`; only i386 re-runs syscalls | `tci.c`, `linux-user/main.c` | ~100 lines |
| Filtering: library map from `load_elf_image` and mmaps of fd ≥ 30, `-tracelibraries`, `-gatetrace` | `tci.c`, `elfload.c`, `syscall.c`, `main.c` | ~80 lines |
| Disassembly into the global `/tmp/qira_asm` (Intel syntax, ARM thumb marker) | `disas.c`, `tci.c` | ~25 lines |

## 2. Cost of a rebase onto current QEMU

* The hooks live **inside the TCG interpreter**. TCI was rewritten in QEMU 6.0 (new bytecode,
  ops and calling convention) and is still only a slow fallback (`--enable-tcg-interpreter`,
  "TCG with bytecode interpreter (slow)" in QEMU 11.1.3's `meson_options.txt`). Every op handler
  hook and the TB-entry code would have to be written again, not ported.
* linux-user changed a lot since 2.5: `main.c` split, per-target `cpu_loop.c`, `syscall.c` and
  `strace.c` restructured, logging through `qemu_log`. The kernel-access hooks and the arg parsing
  would have to be re-done as well.
* Result: a private QEMU fork, rebuilt for every target and updated on every QEMU release, that
  only runs on TCI (several times slower than normal TCG). No distribution ships TCI builds.

Estimate: 3–5 weeks for x86_64 parity, plus ongoing maintenance. Not recommended.

## 3. What the plugin API can do

`QEMU_PLUGIN_VERSION` per release: 8.2 → 1, 9.0 → 2, 9.1 → 3, 9.2/10.0 → 4, 10.1/10.2 → 5,
11.0 → 6, **11.1 → 7**. The header moved from `include/qemu/qemu-plugin.h` to
`include/plugins/qemu-plugin.h` in 11.0. Checked in the headers of each release:

| Needed for | API | First release |
|---|---|---|
| Per-instruction callback (`I`) | `qemu_plugin_register_vcpu_insn_exec_cb` | ≤ 8.2 |
| Memory accesses (`L`/`S`) with values | `qemu_plugin_register_vcpu_mem_cb` + `qemu_plugin_mem_get_value` | 9.2 |
| Register reads (for `W` records by diffing) | `qemu_plugin_get_registers`, `qemu_plugin_read_register` | 9.0 |
| Reading guest memory (kernel-written buffers, `_base`) | `qemu_plugin_read_memory_vaddr` | 9.2 |
| Syscalls (strace, mmap tracking) | `register_vcpu_syscall_cb` / `_syscall_ret_cb` | ≤ 8.2 |
| Disassembly (`<id>_asm`) | `qemu_plugin_insn_disas` | ≤ 8.2 |
| Main binary range (filtering) | `qemu_plugin_start_code`/`end_code`/`entry_code` | ≤ 8.2 |
| Fork/replay: write registers and memory | `qemu_plugin_write_register`, `qemu_plugin_write_memory_vaddr` | 10.1 |
| Fork/replay: return recorded syscall results | `qemu_plugin_register_vcpu_syscall_filter_cb` | 11.0 |
| Set the PC | `qemu_plugin_set_pc` | 11.0 |
| Callback signatures with `userdata` (source incompatible with ≤ 11.0) | — | 11.1 |

**Gaps and workarounds**

* **Register reads (`R` records)** cannot be observed: the API reads register values, it does not
  report which registers an instruction read. The legacy trace has them (186 in the `loop` capture;
  the UI uses them for `regread` highlighting). Workaround: derive reads from the instruction with
  capstone (`regs_access`), which the middleware already uses. Register **writes** are found by
  diffing the registers at each instruction boundary.
* **Register addresses:** the API names registers the way gdb does (x86_64: `rax rbx rcx rdx rsi
  rdi rbp rsp r8…r15 rip eflags cs…`, seen in the spike), in a different order from
  `middleware/arch.py` (`RAX RCX RDX RBX …`, i.e. `CPUArchState` order). The plugin must map by
  name and emit `index_in_arch_list * regsize`, as §1 of UPGRADE.md already requires.
* **Kernel writes into guest memory** are not visible to plugins (the legacy tracer hooked
  `lock_user`). Workaround: in the syscall-return callback, read the output buffers of the
  syscalls that write user memory (`read`, `pread64`, `readv`, `recvfrom`, `recvmsg`, `fstat`,
  `newfstatat`, `getdents64`, …) with `qemu_plugin_read_memory_vaddr` and emit byte `S` records.
  A per-arch table, like QEMU's own strace tables.
* **strace text:** the syscall callback gives the number and raw arguments only. The plugin needs
  its own name/format table (at least for the calls `read_strace_file` parses: `open`/`openat`,
  `mmap`), or it writes structured records and the middleware formats them.
* **Fork/replay:** the legacy approach (write the parent's memory and register bytes, then run)
  breaks for memory the child has not mapped yet. With API 6+ a deterministic re-run is possible:
  run the child from the start, return the parent's recorded syscall results through the syscall
  filter until `start_clnum` (and write the kernel-written buffers), then apply `<id>_mods` with
  the write APIs. Needs QEMU ≥ 11.0. Still the riskiest part (threads, signals, time/random
  syscalls).
* **API churn:** version 7 changed every callback signature. The plugin must be built against the
  QEMU it runs in. Pin one QEMU release, and check `qemu_plugin_version` at load time.

## 4. Debian 13 and nixpkgs

* **Debian 13 `qemu-user` (1:10.0.13+ds-0+deb13u1): no.** The package is "QEMU user mode
  emulation (static binaries)", and QEMU's configure rejects plugins in static builds
  ("static and plugins are mutually incompatible", `configure` of v10.0.0). `apt-cache search`
  lists no other user-mode QEMU (only `qemu-user`, `qemu-user-binfmt` and the transitional
  `qemu-user-static`). Even a dynamic build of 10.0 would have API 4: tracing only, no fork/replay.
* **nixpkgs `qemu-user` at the `devenv.lock` pin (`674a202`): yes.** `pkgs.qemu-user` is
  `qemu.override { userOnly = true; }`, version **11.1.2**, `pluginsSupport ? !isStatic` (on), and
  QEMU's meson installs `qemu-plugin.h` into `$out/include` (single `out` output). Not verified
  from the sandbox: that `cache.nixos.org` has the build (it is a standard package, so it should).

## 5. Other options

| Option | Verdict |
|---|---|
| QEMU TCG plugin | **Chosen.** Upstream, no fork, all QEMU user-mode architectures, cross-architecture tracing (ARM/MIPS/PPC binaries on an x86_64 host, which QIRA supports today), Wine path for Windows (Stage 1B). |
| DynamoRIO (Linux) | Fast, can read/write registers and intercept syscalls, but native only (x86/AArch64/RISC-V hosts): no ARM-on-x86 or MIPS/PPC tracing. Keep for Windows (Stage 5). |
| Intel PIN (`tracers/pin/`) | Proprietary licence, x86 only, `qirapin.cpp` targets an old PIN release. Keep as an optional legacy backend at most. |
| Valgrind tool | Sees loads/stores with values (VEX IR), but it is slow, a tool is a large C project, no cross-architecture emulation, and register writes for fork need client requests. |
| rr | Record/replay of whole processes, not a per-instruction change log; x86/AArch64 only; needs perf counters (often missing in VMs). |

## 6. Build dependencies

**Plugin** (any route): a C compiler, `pkg-config`, glib 2 headers, and `qemu-plugin.h` of the
QEMU it runs in.

**nixpkgs / devenv** (development): add to `devenv.nix`:

```nix
packages = [ pkgs.qemu-user pkgs.glib.dev pkgs.pkg-config ];
```

and build the plugin with `-I ${pkgs.qemu-user}/include`.

**Debian 13 / install.sh** (QEMU from source, pinned to v11.1.x):

```
sudo apt-get install -y build-essential git meson ninja-build pkg-config libglib2.0-dev python3-venv flex bison
```

All of these are already installed on devserver-01. QEMU's subprojects come from gitlab.com by
default; `keycodemapdb`, `berkeley-softfloat-3` and `berkeley-testfloat-3` are mirrored at
`github.com/qemu/<name>`. Configure needs PyPI for its build venv (`wheel`).

```
git clone --depth 1 --branch v11.1.3 https://github.com/qemu/qemu.git
# subprojects at the revisions in subprojects/<name>.wrap, plus subprojects/packagefiles/<name>/
../configure --target-list=x86_64-linux-user,i386-linux-user,aarch64-linux-user,arm-linux-user,mips-linux-user,mipsel-linux-user,ppc-linux-user \
             --enable-plugins --disable-docs --disable-rust --disable-werror
ninja qemu-x86_64 qemu-i386 …
```

`x86_64-linux-user` alone built in **80 s** on 4 CPUs here.

## 7. Spike

`tracers/qemu-plugin/spike/qira_spike.c` (a spike, not the tracer): writes the 24-byte change log
with `I` records for main-binary instructions and `S` records for stores from all code at the
current clnum, like the legacy tracer without `-tracelibraries`. Built against QEMU 11.1.3 from
source (`$TMPDIR`), run as
`qemu-x86_64 -plugin libqira_spike.so,out=<file> qira_tests/bin/loop`.

| | Spike (QEMU 11.1.3, Debian 13 glibc 2.41) | Legacy (`samples/legacy/0`, QEMU 2.5.1 TCI, Ubuntu 16.04 glibc 2.23) |
|---|---|---|
| Program output | `0`…`4`, exit 2 | the same |
| `I` records | 149, clnums 1–149 | 149, clnums 1–149 |
| `(clnum, pc, size)` sequence | **identical** | |
| `S` records | 12,489 (11,092 at clnum 0 = loader/libc start-up) | 12,330 (10,778 at clnum 0) |
| Clnums ≥ 1 with the same store count | 32 of 42 | |
| Other record types | none (spike) | `L` 35,033, `W` 579, `R` 186 |

The 10 clnums with a different store count are calls into libc (`__libc_start_main` at 16,
the `printf` calls, `exit`), which ran a different glibc; the spike also does not record kernel
writes yet. Fixes found on the way: `qemu_plugin_start_code()` is not valid in
`qemu_plugin_install` (segfault; query it on the first translation), and API 7 callback signatures.

Not measured: throughput (the `loop` run is too short to matter; Stage 1A benchmarks it).

## 8. What this changes in the plan

* **§3 1A:** pin QEMU **11.1.x** (API 7; write APIs since 10.1, syscall filter since 11.0); `R`
  records from capstone, not the plugin; kernel writes from a per-syscall buffer table; fork as a
  deterministic re-run with the syscall filter; register mapping by name.
* **Task 4 needs a tracer that does not exist yet.** The legacy fork cannot be built, and the plugin
  is only a spike. New **Task 5** before Task 4: a minimal plugin tracer that the legacy middleware
  can use (x86_64 first: `I`/`L`/`S`/`W`, `_strace`, `_base`, `<id>_asm` or `/tmp/qira_asm`,
  filtering, `-gatetrace`, `-tracelibraries`; no fork), with `qira_program.execqira` building the
  `-plugin` command line. Task 4 then installs QEMU 11.1.x + that plugin.
* **devenv:** add `qemu-user`, `glib.dev`, `pkg-config` to `devenv.nix` in Task 5 (the user enters
  the shell once).

## Exact `install.sh` step for Task 4

```
# tracer: QEMU 11.1.x user mode with plugins + libqira.so (from Task 5), into the data folder
TRACERS=${XDG_DATA_HOME:-$HOME/.local/share}/qira/tracers
QEMU_TAG=v11.1.3
# 1. build QEMU (as in section 6) in a temp dir, for the targets QIRA supports
# 2. install bin/qemu-<arch> as $TRACERS/qemu/qemu-<arch> (keep the qira-<arch> names as symlinks)
# 3. build tracers/qemu-plugin with -I <qemu>/include/plugins, install as $TRACERS/qemu/libqira.so
# 4. record QEMU_TAG and the plugin API version in $TRACERS/qemu/VERSION
```

Behind `--with-tracer` (default on). Skipped with a message when build dependencies are missing
(print the `apt-get` line). In the devenv shell, use `pkgs.qemu-user` instead of building QEMU.
