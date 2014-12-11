import sys
sys.path.append("static2/")
import static2

def test():
  static = static2.Static('qira_tests/bin/loop', debug=1)
  static.process()

