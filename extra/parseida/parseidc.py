import sys
import collections

def ghex(a):
  if a == None:
    return None
  return hex(a).strip("L")

tags = collections.defaultdict(dict)

for ln in open(sys.argv[1]).read().split("\n"):
  ln = ln.strip(" \n\t")
  if ln.startswith("MakeName"):
    (addr,name) = ln.split("(")[1].split(")")[0].split(",")
    addr = addr.strip(" \t")
    name = name.strip(" \t\"")
    addr = ghex(int(addr, 16))
    tags[addr]['name'] = name
  
tags = dict(tags)
print tags

# upload the tags

from socketIO_client import SocketIO, BaseNamespace
class QiraNamespace(BaseNamespace):
  pass

sio = SocketIO('localhost', 3002)
qira = sio.define(QiraNamespace, '/qira')
qira.emit("settags", dict(tags))

