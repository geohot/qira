import sys
sys.path.append("middleware/")
import qira_program
import time
import pytest

@pytest.mark.skipif(sys.platform == "darwin", reason="QEMU tracer binaries are Linux-only")
def test():
  program = qira_program.Program("qira_tests/bin/loop")
  program.execqira(shouldfork=True)
  time.sleep(1)
  
