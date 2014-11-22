import sys
sys.path.append("middleware/")
import qira_program
import time

def test():
  program = qira_program.Program("test/bin/loop")
  program.execqira(shouldfork=True)
  time.sleep(1)
  

