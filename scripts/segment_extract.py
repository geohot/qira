from qira_log import *

from pymongo import MongoClient
db = MongoClient('localhost', 3001).meteor

mem_addrs = set()
ins_addrs = set()

# page level granularity
dat = read_log("/tmp/qira_log")
for (address, data, clnum, flags) in dat:
  if flags & IS_MEM:
    mem_addrs.add(address & 0xFFFFF000)
  if flags & IS_START:
    ins_addrs.add(address & 0xFFFFF000)

pmaps = []

print "instructions"
for i in sorted(ins_addrs):
  pmaps.append({"address": i, "type": "instruction"})

print "memory"
for i in sorted(mem_addrs):
  if i not in ins_addrs:
    pmaps.append({"address": i, "type": "memory"})


coll = db.pmaps
print "doing db insert"
coll.drop()
coll.insert(pmaps)
print "db insert done, building indexes"
coll.ensure_index("address")
print "indexes built"

