from pymongo import MongoClient
from qira_log import *

db = MongoClient('localhost', 3001).meteor

print "reading log"
dat = read_log("/tmp/qira_log")

print "building database data"

ds = []

for (address, data, clnum, flags) in dat:
  if flags & IS_START:
    typ = "I"
  elif flags & IS_WRITE and flags & IS_MEM:
    typ = "S"
  elif not flags & IS_WRITE and flags & IS_MEM:
    typ = "L"
  elif flags & IS_WRITE and not flags & IS_MEM:
    typ = "W"
  elif not flags & IS_WRITE and not flags & IS_MEM:
    typ = "R"

  d = {'address': address, 'type': typ, 'size': flags&SIZE_MASK, 'clnum': clnum}
  d['data'] = data
  ds.append(d)

#coll = db.tinychange
coll = db.change
print "doing db insert of",len(ds),"changes"
coll.drop()
coll.insert(ds)
print "db insert done, building indexes"
coll.ensure_index("data")
coll.ensure_index([("data", 1), ("address", 1)])
coll.ensure_index("address")
coll.ensure_index("clnum")
coll.ensure_index([("address", 1), ("type", 1)])
print "indexes built"

