from pymongo import MongoClient
from qira_log import *
from function_analysis import *
from loop_analysis import *

db = MongoClient('localhost', 3001).meteor

print "reading log"
dat = read_log("/tmp/qira_log")
fxns = do_function_analysis(dat)
print fxns

print "building blocks data"

# look at addresses
# if an address can accept control from two addresses, it starts a basic block
# if an address can give control to two addresses, it ends a basic block
#   so add those two addresses to the basic block breaker set


# address = [all that lead into it]
prev_map = {}
next_map = {}

# address

prev = None
next_instruction = None

basic_block_starts = set()

for (address, data, clnum, flags) in dat:
  if not flags & IS_START:
    continue
  if next_instruction != None and next_instruction != address:
    # anytime we don't run the next instruction in sequence
    # this is a basic block starts
    # print next_instruction, address, data
    basic_block_starts.add(address)

  if address not in prev_map:
    prev_map[address] = set()
  if prev not in next_map:
    next_map[prev] = set()

  prev_map[address].add(prev)
  next_map[prev].add(address)
  prev = address
  next_instruction = address + data

#print prev_map
#print next_map

# accepts control from two addresses
for a in prev_map:
  if len(prev_map[a]) > 1:
    basic_block_starts.add(a)
# gives control to two addresses
for a in next_map:
  if len(next_map[a]) > 1:
    for i in next_map[a]:
      basic_block_starts.add(i)

#print basic_block_starts

blocks = []
cchange = None
last = None

for (address, data, clnum, flags) in dat:
  if not flags & IS_START:
    continue
  if cchange == None:
    cchange = (clnum, address)
  if address in basic_block_starts:
    blocks.append({'clstart': cchange[0], 'clend': last[0], 'start': cchange[1], 'end': last[1], 'depth': get_depth(fxns, cchange[0])})
    cchange = (clnum, address)
  last = (clnum, address)

blocks.append({'clstart': cchange[0], 'clend': last[0], 'start': cchange[1], 'end': last[1], 'depth': get_depth(fxns, cchange[0])})

(blocks, loops) = do_loop_analysis(blocks)

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

