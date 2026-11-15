import os
import time

import pytest

from qira.legacy import qira_config, qira_program
from conftest import LOOP

LEGACY_TRACER = os.path.join(qira_config.TRACER_DIR, "qemu", "qira-x86_64")


def _have_tracer():
  import shutil
  if os.path.exists(LEGACY_TRACER):
    return True
  # plugin tracer: an upstream qemu-x86_64 plus the built plugin
  qemu = shutil.which("qemu-x86_64") or (qira_config.TRACER_DIR + "qemu/qemu-x86_64")
  return os.path.exists(qira_config.QEMU_PLUGIN) and (os.path.exists(qemu) or shutil.which("qemu-x86_64"))


@pytest.mark.skipif(not _have_tracer(),
                    reason="no tracer: build the plugin (make -C tracers/qemu-plugin) in the devenv "
                           "shell, or provide %s (UPGRADE.md Task 5)" % LEGACY_TRACER)
def test_loop_runs(tmp_path, monkeypatch):
  # trace into an isolated dir so a running server's /tmp/qira_logs is left alone
  d = tmp_path / "logs"
  d.mkdir()
  monkeypatch.setattr(qira_config, "TRACE_FILE_BASE", str(d) + "/")
  monkeypatch.setattr(qira_config, "ASM_FILE", str(tmp_path / "qira_asm"))

  program = qira_program.Program(LOOP)
  program.clear()
  proc = program.execqira(shouldfork=True)
  deadline = time.time() + 15
  while not os.path.isfile(str(d / "0")):
    assert time.time() < deadline, "tracer did not create a log"
    time.sleep(0.1)
  if proc is not None:
    proc.wait(timeout=15)
