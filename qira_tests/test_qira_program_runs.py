import os
import time

import pytest

from qira import qira_config, qira_program
from conftest import LOOP

TRACER = os.path.join(qira_config.TRACER_DIR, "qemu", "qira-x86_64")


@pytest.mark.skipif(not os.path.exists(TRACER),
                    reason="QEMU tracer %s does not resolve (build it, or see UPGRADE.md Task 2/3)" % TRACER)
def test_loop_runs():
  # the tracer writes to /tmp/qira_logs and /tmp/qira_asm itself
  program = qira_program.Program(LOOP)
  program.clear()
  program.execqira(shouldfork=True)
  deadline = time.time() + 10
  while not os.path.isfile(os.path.join(qira_config.TRACE_FILE_BASE, "0")):
    assert time.time() < deadline, "tracer did not create a log"
    time.sleep(0.1)
