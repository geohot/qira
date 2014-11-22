import sys
sys.path.append("static2/")
import static2

def test():
  static = static2.Static('test/bin/loop', debug=True)
  static.process()
  

