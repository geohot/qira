from qira_log import *
from pymongo import MongoClient

def is_library_address(address):
  return address > 0x80000000

db = MongoClient('localhost', 3001).meteor

print "reading log"
dat = read_log("/tmp/qira_log")

print "filtering data"
ds = []
dds = []

maxclnum = 0 
fixclnum = 0

clignore = 0

for (address, data, clnum, flags) in dat:
  if clnum > maxclnum:
    maxclnum = clnum
  if flags & IS_START:
    if is_library_address(address):
      clignore = clnum
    else:
      fixclnum += 1
  dds.append((address, data, fixclnum, flags))
  if clnum == clignore and not (flags & IS_MEM):
    continue
  ds.append((address, data, fixclnum, flags))

print "filtered from %d(%d) to %d(%d)" % (maxclnum, len(dat), clnum, len(ds))
write_log("/tmp/qira_log", dds)
write_log("/tmp/qira_log_filtered", ds)

