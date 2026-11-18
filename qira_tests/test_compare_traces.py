"""Unit tests for qira_tests/compare_traces.py (the Task 2 trace-diff tool).

Pure logic on synthetic traces built from conftest's LOOP_CHANGES fixture; no
tracer, subprocess or network.
"""
import struct

import pytest

from qira.legacy import qira_log

import compare_traces as ct
from conftest import LOOP, LOOP_CHANGES

pytestmark = pytest.mark.unit

X64 = ct.ARCHES["x86-64"]


def _write_trace(d, changes, base_text, strace_text="", env=False, asm=None):
  """Write a numbered trace 0 (log + sidecars) into directory d."""
  d.mkdir(parents=True, exist_ok=True)
  qira_log.write_log(str(d / "0"), changes)
  with open(d / "0", "r+b") as f:        # parent_id = -1 (top-level run)
    f.seek(0x10)
    f.write(struct.pack("i", -1))
  (d / "0_base").write_text(base_text)
  if strace_text:
    (d / "0_strace").write_text(strace_text)
  if env:
    (d / "0_env").write_bytes(b"\x00" * 16)
  if asm is not None:
    (d / "0_asm").write_text(asm)
  return d


# --------------------------------------------------------------------------
# loading / parsing
# --------------------------------------------------------------------------

def test_load_header_and_type_counts(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  assert t.count == len(LOOP_CHANGES) + 1      # header entry is counted
  assert t.parent_id == -1
  counts = t.type_counts()
  assert counts["I"] == 4                       # four IS_START records
  assert counts["R"] == 3 and counts["W"] == 7  # register reads / writes
  assert counts["S"] == 2 and counts["L"] == 0  # memory stores / loads


def test_insns_are_is_start_records(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  pcs = [pc for (_clnum, pc, _sz) in t.insns]
  assert pcs == [0x400536, 0x400537, 0x40053A, 0x40053E]


def test_base_parsing_and_main_module(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  assert len(t.modules) == 3                     # loop x2 segments + [vdso]
  assert t.main_module().start == 0x400000       # lowest-address module
  assert t.module_for(0x400540).name == "loop"
  assert t.module_for(0x7ffff7ffa000).name == "[vdso]"
  assert t.module_for(0x123) is None


def test_strace_parsing_skips_garbage(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  # the fixture's _strace has 4 valid lines and one "garbage line"
  assert [s.name for s in t.strace] == ["open", "mmap", "write", "exit_group"]
  assert t.strace[0].ret == "3"
  assert t.strace[-1].name == "exit_group"


def test_sidecar_presence_flags(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  assert t.has_env is False          # loop_trace writes no _env
  assert t.has_asm is False


# --------------------------------------------------------------------------
# normalisation + register reconstruction
# --------------------------------------------------------------------------

def test_main_insn_offsets_are_module_relative(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  seq, name = ct._main_insn_offsets(t)
  assert name == "loop"
  assert [off for (off, _sz, _cl) in seq] == [0x536, 0x537, 0x53A, 0x53E]


def test_register_file_tracks_named_registers(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  snaps = list(ct.register_file(t.changes, X64))
  assert len(snaps) == 4                         # one per instruction
  # RSP/RBP/RIP are written in LOOP_CHANGES and should appear in the state
  last_regs = snaps[-1][2]
  assert "RSP" in last_regs and "RIP" in last_regs


# --------------------------------------------------------------------------
# comparisons
# --------------------------------------------------------------------------

def test_compare_identical_trace_reports_no_diffs(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  head, lines = ct.cmp_main_insns(t, t, 10)
  assert "diffs" not in head
  assert any("identical" in ln for ln in lines)
  # type counts all zero-delta
  _h, tlines = ct.cmp_type_counts(t, t)
  assert all(ln.endswith("+0") for ln in tlines if ln.strip().startswith(("I", "L", "S", "R", "W")))


def test_cmp_main_insns_detects_changed_pc(loop_trace, tmp_path):
  a = ct.load_trace(str(loop_trace), "0")
  # trace B: same as A but the last instruction executes a different pc
  changes = list(LOOP_CHANGES)
  changes[12] = (0x4005FE, 7, 3, qira_log.IS_VALID | qira_log.IS_START)
  base = (loop_trace / "0_base").read_text()
  b_dir = _write_trace(tmp_path / "b", changes, base)
  b = ct.load_trace(str(b_dir), "0")
  head, lines = ct.cmp_main_insns(a, b, 10)
  assert "diffs" in head
  assert any("#3" in ln for ln in lines)         # fourth main instruction differs


def test_cmp_type_counts_flags_missing_r_records(loop_trace, tmp_path):
  a = ct.load_trace(str(loop_trace), "0")
  # trace B: drop every register-read (R) record
  changes = [c for c in LOOP_CHANGES
             if ct.qira_log.flag_to_type(c[3]) != "R"]
  base = (loop_trace / "0_base").read_text()
  b = ct.load_trace(str(_write_trace(tmp_path / "b", changes, base)), "0")
  head, _lines = ct.cmp_type_counts(a, b)
  assert "no R records" in head


def test_cmp_modules_reports_missing_modules(loop_trace, tmp_path):
  a = ct.load_trace(str(loop_trace), "0")
  # trace B: only the main binary mapped (no [vdso]) — the plugin's situation
  b_base = "0000000000400000-0000000000401000 0 %s\n" % LOOP
  b = ct.load_trace(str(_write_trace(tmp_path / "b", list(LOOP_CHANGES), b_base)), "0")
  head, lines = ct.cmp_modules(a, b)
  assert "missing" in head
  assert any("[vdso]" in ln for ln in lines)


def test_cmp_syscalls_flags_unresolved_names(loop_trace, tmp_path):
  a = ct.load_trace(str(loop_trace), "0")
  base = (loop_trace / "0_base").read_text()
  b_strace = "0 10 syscall_12(0x0) = 0\n1 10 syscall_1(0x1,0x2,0x3) = 6\n"
  b = ct.load_trace(str(_write_trace(tmp_path / "b", list(LOOP_CHANGES), base,
                                     strace_text=b_strace)), "0")
  head, lines = ct.cmp_syscalls(a, b, 10)
  assert "unresolved" in head
  assert any("A=0" in ln and "B=2" in ln for ln in lines)


def test_render_runs_full_compare(loop_trace):
  t = ct.load_trace(str(loop_trace), "0")
  text = ct.render(ct.compare(t, t, X64, 5))
  assert "logstate header" in text
  assert "main-binary instruction sequence" in text
  assert "syscall list" in text
