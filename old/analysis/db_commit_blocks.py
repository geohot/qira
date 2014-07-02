from pymongo import MongoClient
from qira_log import *
from function_analysis import *
from loop_analysis import *
from block_analysis import *

db = MongoClient('localhost', 3001).meteor

print "reading log"
dat = read_log("/tmp/qira_log")
fxns = do_function_analysis(dat)
print fxns

print "building blocks data"

blocks = do_block_analysis(dat)

for b in blocks:
  b['depth'] = get_depth(fxns, b['clstart'])

(blocks, loops, realblocks, realtrace) = do_loop_analysis(blocks)

print realtrace

coll = db.fxns
print "doing fxns insert"
coll.drop()
coll.insert(fxns)
print "db insert done, building indexes"
coll.ensure_index("clstart")
coll.ensure_index("clend")
print "indexes built"

coll = db.loops
print "doing loops insert"
coll.drop()
coll.insert(loops)
print "db insert done, building indexes"
coll.ensure_index("blockidx")
print "indexes built"

coll = db.realblocks
print "doing db insert"
coll.drop()
coll.insert(realblocks)
print "db insert done, building indexes"
coll.ensure_index("start")
coll.ensure_index("idx")
print "realblocks idx built"

coll = db.blocks
print "doing db insert"
coll.drop()
coll.insert(blocks)
print "db insert done, building indexes"
coll.ensure_index("clstart")
coll.ensure_index("clend")
coll.ensure_index("start")
coll.ensure_index("end")
print "indexes built"

