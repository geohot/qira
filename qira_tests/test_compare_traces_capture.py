"""Functional test: capture a live plugin trace of loop and diff it against the
legacy reference capture with compare_traces.

Skipped unless an upstream qemu-x86_64, the built plugin, and samples/legacy/0
are all present. Documents, as assertions, the differences Task 2 classifies:
the main-binary instruction sequence is identical, while the plugin currently
emits no R records, maps fewer modules, and leaves syscall names unresolved.
"""
import os
import shutil
import time

import pytest

from qira.legacy import qira_config, qira_program

import compare_traces as ct
from conftest import LOOP, LEGACY

qemu = shutil.which("qemu-x86_64") or (
    (qira_config.TRACER_DIR + "qemu/qemu-x86_64")
    if os.path.exists(qira_config.TRACER_DIR + "qemu/qemu-x86_64") else None)

pytestmark = [
    pytest.mark.functional,
    pytest.mark.skipif(qemu is None, reason="no qemu-x86_64 (enter the devenv shell)"),
    pytest.mark.skipif(not os.path.exists(qira_config.QEMU_PLUGIN),
                       reason="libqira.so not built (run: make -C tracers/qemu-plugin)"),
    pytest.mark.skipif(not os.path.exists(os.path.join(LEGACY, "0")),
                       reason="samples/legacy/0 not present (local only)"),
]


@pytest.fixture
def port_capture(tmp_path, monkeypatch):
  """Capture a plugin trace of loop into tmp_path; return the directory."""
  d = tmp_path / "port"
  d.mkdir()
  monkeypatch.setattr(qira_config, "TRACE_FILE_BASE", str(d) + "/")
  monkeypatch.setattr(qira_config, "ASM_FILE", str(d / "0_asm"))
  p = qira_program.Program(LOOP)
  assert p.use_plugin, "plugin not selected for an x86_64 ELF"
  proc = p.execqira(shouldfork=True)
  proc.wait(timeout=30)
  deadline = time.time() + 10
  while not (d / "0").exists() or (d / "0").stat().st_size < 0x18:
    assert time.time() < deadline, "tracer wrote no log"
    time.sleep(0.05)
  return d


def test_main_instruction_sequence_is_identical(port_capture):
  legacy = ct.load_trace(LEGACY, "0")
  port = ct.load_trace(str(port_capture), "0")
  head, lines = ct.cmp_main_insns(legacy, port, 5)
  assert "diffs" not in head, "\n".join(lines)
  assert any("identical" in ln for ln in lines)
  # same number of instruction-start records and same final clnum
  assert legacy.type_counts()["I"] == port.type_counts()["I"] == 149


def test_known_plugin_gaps_are_reported(port_capture):
  legacy = ct.load_trace(LEGACY, "0")
  port = ct.load_trace(str(port_capture), "0")

  # the plugin emits no register-read (R) records yet (Stage 1A)
  assert legacy.type_counts()["R"] > 0
  assert port.type_counts()["R"] == 0
  assert "no R records" in ct.cmp_type_counts(legacy, port)[0]

  # it maps only the main binary, not the shared libraries
  mhead, _ = ct.cmp_modules(legacy, port)
  assert "missing" in mhead
  assert len(port.modules) < len(legacy.modules)

  # syscalls are recorded but names are left unresolved (syscall_<n>)
  shead, _ = ct.cmp_syscalls(legacy, port, 5)
  assert "unresolved" in shead

  # and no _env sidecar is written
  assert legacy.has_env and not port.has_env
