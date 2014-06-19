import struct
from pymongo import MongoClient

db = MongoClient('localhost', 3001).meteor

dat = open("/tmp/qira_log").read()

IS_VALID = 0x80000000
IS_WRITE = 0x40000000
IS_MEM =   0x20000000
SIZE_MASK = 0xFF

print "building database data"

ds = []

for i in range(0, len(dat), 0x18):
  (address, data, clnum, flags) = struct.unpack("QQII", dat[i:i+0x18])
  if not flags & IS_VALID:
    break

  if flags & IS_WRITE and flags & IS_MEM:
    typ = "S"
  elif not flags & IS_WRITE and flags & IS_MEM:
    typ = "L"
  elif flags & IS_WRITE and not flags & IS_MEM:
    typ = "W"
  elif not flags & IS_WRITE and not flags & IS_MEM:
    typ = "R"

  d = {'address': address, 'type': typ, 'size': flags&SIZE_MASK, 'clnum': clnum}
  if flags & IS_WRITE:
    d['data'] = data
  ds.append(d)

coll = db.tinychange
print "doing db insert"
coll.drop()
coll.insert(ds)
print "db insert done, building indexes"
coll.ensure_index("address")
coll.ensure_index("clnum")
coll.ensure_index([("address", 1), ("type", 1)])
print "indexes built"

