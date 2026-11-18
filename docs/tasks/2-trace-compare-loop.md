# Task 2 — Compare the port's trace of `loop` with the legacy capture

**Branch:** `feature/trace-compare-loop` · **Date:** 2026-11-18

## Goal

List every difference between a trace of `qira_tests/bin/loop` taken with the Python 3 middleware
and the QEMU plugin tracer (Task 5) and the legacy reference capture in `samples/legacy/`, each
explained as expected (libc, QEMU version, paths) or as a bug in the port or the plugin.

## What was done

* Added **`qira_tests/compare_traces.py`** — a trace-directory diff tool kept for later stages. It
  reuses the in-repo reader (`qira.legacy.qira_log.read_log` / `flag_to_type`) and the arch register
  tables (`qira.legacy.arch`) instead of re-parsing the binary format, and compares: the `logstate`
  header, per-type record counts (`I`/`L`/`S`/`R`/`W`), the main binary's instruction sequence
  (normalised to a module-relative offset so base/ASLR differences do not matter), register values
  at matched main-binary instructions, the `_strace` syscall list, the `_base` module list, and the
  presence of `_env`/`_asm`.
* Captured a **port** trace with the plugin tracer into `samples/port/` (local only, git-ignored):

  ```
  QIRA_TRACER_DIR=$PWD/tracers QIRA_TRACE_DIR=samples/port QIRA_ASM_FILE=samples/port/0_asm \
    timeout 25 ./qira --web-port 3011 --socat-port 4010 qira_tests/bin/loop
  ```

  (run from the devenv shell so `qemu-x86_64` and `libqira.so` are found). Output of the comparison
  is saved locally at `samples/port-compare.txt`.
* The optional **legacy-binary copy** leg (step 1/2 of the task: `podman cp` the Ubuntu 16.04
  `qemu-x86_64` and a xenial sysroot to separate tracer differences from libc differences) was
  **not done** — it needs podman, which only the user runs (A5). The comparison is therefore
  port-capture vs the committed legacy capture; see "Not verified" below.

## How it was verified

* `uv run pytest -m unit` → **36 passed** (13 new in `test_compare_traces.py`).
* `uv run pytest qira_tests/test_compare_traces_capture.py` (functional) → **2 passed** (captures a
  live plugin trace and diffs it against `samples/legacy/0`).
* `python qira_tests/compare_traces.py samples/legacy samples/port` → the summary below.

### Headline result

The main binary's instruction stream is reproduced **exactly**: 149 `I` records in both, and an
**identical** normalised `(offset, size)` sequence for all 149 instructions. This matches Task 5's
finding and is also covered by `test_plugin_tracer.py::test_instruction_sequence_matches_legacy`.

## Differences (category · legacy A · port B · cause · expected?)

| Category | Legacy (A) | Port (B) | Cause | Expected? |
|---|---|---|---|---|
| Entry count | 48278 | 43062 | Different libc (Ubuntu 16.04 `glibc 2.23` vs Debian 13) runs different library code; plugin also emits fewer register/mem records | Yes |
| `I` (instructions) | 149 | 149 | — identical | Yes (match) |
| Main insn sequence | 149 insns | 149 insns, identical | same binary, same load base `0x400000` (non-PIE) | Yes (match) |
| `R` (reg reads) | 186 | **0** | Plugin API cannot see register reads; deferred to Stage 1A (derive from capstone) | Yes — known gap |
| `W` (reg writes) | 579 | 213 | Plugin only emits a `W` when a tracked register changes; no per-insn `RIP` write | Yes — known gap |
| `L` / `S` (mem) | 35033 / 12330 | 29901 / 12798 | Different libc memory traffic | Yes |
| Register values at matched insns | — | all 149 positions differ | libc/stack pointers live at `0x4000…` (geohot fork) vs `0x7fe9…` (upstream QEMU mmap base); `RAX/RDX` initial values differ by QEMU version; stale `RIP` because of the missing `W` records above | Yes — ASLR/QEMU-version + known `R`/`W` gap |
| `_strace` count | 29 | 45 | Debian glibc probes more paths (`openat`/`newfstatat`/`getrandom`) | Yes |
| `_strace` names | resolved (`brk`, `openat`, …) | **`syscall_<n>`**, undecoded hex args | Plugin does not map syscall numbers to names / decode args yet | Yes — known gap (Stage 1A) |
| `_base` modules | 25 maps / 11 names | 2 maps / 1 name (main binary only) | Plugin does not track library `mmap`s yet | Yes — known gap (Stage 1A) |
| `_env` sidecar | present | **absent** | Plugin does not dump the initial stack/env region | Yes — known gap (Stage 1A) |
| `_asm` listing | global `/tmp/qira_asm` (not per-run) | `0_asm` created but **empty** | Plugin takes `asm=` but does not populate it yet | Yes — known gap (Stage 1A) |
| Paths in `_base`/`_env` | container paths `/qira/…` | host paths `/home/localadmin/src/qira/…` | different capture host | Yes |

**No difference was classified as a port bug.** Every divergence is either an expected environment
difference (libc version, QEMU version, ASLR, capture paths) or a plugin feature that is explicitly
scheduled for **Stage 1A** (register reads, full `W` records, library mmap tracking, syscall-name
resolution, `_env`, per-run `_asm`). Nothing on the critical path was fixed on this branch because
nothing here is a regression relative to the plan.

## Not verified

* **Tracer-only vs libc-only split.** Without the podman copy of the legacy `qemu-x86_64` and a
  xenial sysroot, the port capture runs against Debian's glibc, so library-level differences and
  tracer differences are not separated. The identical main-binary sequence already shows the tracer
  reproduces the program's own execution; a xenial-sysroot capture (`samples/port-xenial/`) would
  additionally let the library traffic be compared line-for-line. To produce it, run the `podman cp`
  block in UPGRADE.md Task 2 and re-run the capture with `QEMU_LD_PREFIX` pointing at the sysroot.

## Open questions for the user

1. Do you want the xenial-sysroot capture (needs the podman `qemu-x86_64` + `/lib` copy) to get a
   libc-matched comparison, or is the main-binary match enough to close Task 2? The Stage 1A gaps
   above are already tracked, so this is optional.

## What the next task needs to know

* `compare_traces.py` is the reusable diff primitive for Stage 0's golden-fixture checks (Task 9)
  and for the angr-vs-plugin comparison in Task 7. It compares one numbered trace per directory
  (`--id`, default `0`) and takes `--arch` for register naming.
* The Stage 1A work list is confirmed by real data: **register reads, per-instruction `W` records,
  library `mmap` tracking in `_base`, syscall-name/arg resolution in `_strace`, the `_env` dump, and
  populating the per-run `_asm` file.** Golden fixtures (Task 9) captured now will not contain any of
  these until Stage 1A lands.
