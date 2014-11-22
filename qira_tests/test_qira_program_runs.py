import sys
sys.path.append("middleware/")
import qira_program
import time

def test():
  program = qira_program.Program("qira_tests/bin/loop")
  program.execqira(shouldfork=True)
  time.sleep(1)
  

