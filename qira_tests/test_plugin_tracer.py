"""The QEMU plugin tracer (tracers/qemu-plugin/libqira.so) tracing a live binary.

Skipped unless an upstream qemu-x86_64 and the built plugin are both available.
Build the plugin first:  make -C tracers/qemu-plugin   (in the devenv shell).

Checks the trace files the plugin writes (the legacy format), that the instruction
sequence matches the legacy capture when samples/legacy/0 is present, and that the
middleware loads the live trace and answers register/instruction queries.
"""
import os
import shutil
import struct
import subprocess
import time

import pytest

from qira.legacy import qira_config, qira_log, qira_program
from conftest import LOOP, LEGACY, wait_for_update

qemu = shutil.which("qemu-x86_64") or (
    (qira_config.TRACER_DIR + "qemu/qemu-x86_64")
    if os.path.exists(qira_config.TRACER_DIR + "qemu/qemu-x86_64") else None)

pytestmark = [
    pytest.mark.skipif(qemu is None, reason="no qemu-x86_64 (enter the devenv shell)"),
    pytest.mark.skipif(not os.path.exists(qira_config.QEMU_PLUGIN),
                       reason="libqira.so not built (run: make -C tracers/qemu-plugin)"),
]

IS_START = qira_log.IS_VALID | qira_log.IS_START


@pytest.fixture
def trace_into(tmp_path, monkeypatch):
  """An isolated trace dir + asm file for the plugin to write to."""
  d = tmp_path / "logs"
  d.mkdir()
  asm = tmp_path / "qira_asm"
  monkeypatch.setattr(qira_config, "TRACE_FILE_BASE", str(d) + "/")
  monkeypatch.setattr(qira_config, "ASM_FILE", str(asm))
  return d


def _trace(d):
  """Run the plugin tracer on loop into dir d; return the Program."""
  p = qira_program.Program(LOOP)
  assert p.use_plugin, "plugin not selected for an x86_64 ELF"
  proc = p.execqira(shouldfork=True)      # inherits stdio; the plugin writes the trace files
  proc.wait(timeout=30)                   # loop exits non-zero by design; the trace is what matters
  # the log's first record is the header; wait until it is finalised at exit
  deadline = time.time() + 10
  while not (d / "0").exists() or (d / "0").stat().st_size < 0x18:
    assert time.time() < deadline, "tracer wrote no log"
    time.sleep(0.05)
  return p


def _insns(path):
  recs = qira_log.read_log(open(path, "rb"))
  return [(r[2], r[0], r[1]) for r in recs if r[3] & qira_log.IS_START]  # (clnum, pc, size)


def test_plugin_traces_loop(trace_into):
  _trace(trace_into)
  log = trace_into / "0"
  assert log.exists()
  ins = _insns(log)
  assert len(ins) == 149
  assert ins[0][0] == 1 and ins[-1][0] == 149       # clnums 1..149

  # strace: the loader's openat/mmap of libc, in the format read_strace_file parses
  strace = (trace_into / "0_strace").read_text(errors="replace")
  assert "openat(" in strace and "mmap(" in strace
  assert all(len(ln.split()) >= 3 for ln in strace.splitlines() if ln)

  # base: the main binary's load segments, host-readable
  base = (trace_into / "0_base").read_text()
  assert os.path.realpath(LOOP) in base
  first = base.splitlines()[0].split()
  assert "-" in first[0] and int(first[1], 16) >= 0


@pytest.mark.skipif(not os.path.exists(os.path.join(LEGACY, "0")),
                    reason="samples/legacy/0 not present (local only)")
def test_instruction_sequence_matches_legacy(trace_into):
  _trace(trace_into)
  plugin = _insns(trace_into / "0")
  legacy = _insns(os.path.join(LEGACY, "0"))
  # identical (clnum, pc, size) for every instruction
  assert plugin == legacy


def test_middleware_loads_live_trace(trace_into):
  p = _trace(trace_into)
  t = p.add_trace(str(trace_into / "0"), 0)
  try:
    wait_for_update(t.db)
    assert p.get_maxclnum() == {0: [0, 149]}
    # registers reconstruct: RIP at clnum 1 is the first traced instruction's pc
    regs = t.db.fetch_registers(1)
    rip = regs[16]                      # X64REGS index 16 = RIP
    assert rip == _insns(trace_into / "0")[0][1]
  finally:
    t.keep_analysis_thread = False
