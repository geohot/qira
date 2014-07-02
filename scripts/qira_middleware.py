from qira_log import *
from qira_memory import *
import subprocess
import time
import sys
  
from pymongo import MongoClient

instructions = {}

regs = Memory()
mem = Memory()

pmaps = {}

def process(log_entries):
  db = MongoClient('localhost', 3001).meteor
  Change = db.change
  Pmaps = db.pmaps

  db_changes = []
  new_pmaps = pmaps.copy()
  for (address, data, clnum, flags) in dat:
    # Changes database
    this_change = {'address': address, 'type': flag_to_type(flags),
        'size': flags&SIZE_MASK, 'clnum': clnum, 'data': data}
    if address in instructions:
      this_change['instruction'] = instructions[address]
    db_changes.append(this_change)

    # update local regs and mem database
    if flags & IS_WRITE and flags & IS_MEM:
      size = flags & SIZE_MASK
      # support big endian
      for i in range(0, size/8):
        mem.commit(clnum, address+i, data & 0xFF)
        data >>= 8
    elif flags & IS_WRITE:
      size = flags & SIZE_MASK
      # support big endian
      regs.commit(clnum, address, data)

    # for Pmaps
    page_base = address & 0xFFFFF000
    if flags & IS_MEM and page_base not in addrs:
      new_pmaps[page_base] = "memory"
    if flags & IS_START:
      new_pmaps[page_base] = "instruction"
  # *** FOR LOOP END ***

  # we shouldn't be rewriting this every time
  open("/tmp/qira_memdb", "wb").write(
    json.dumps({"regs": regs.dump(), "mem": mem.dump()}))

  # push new pmaps
  db_pmaps = []
  for i in new_pmaps:
    if i not in pmaps or pmaps[i] != new_pmaps[i]:
      pmaps.append({"address": i, "type": new_pmaps[i]})
  Pmaps.insert(db_pmaps)
  pmaps = new_pmaps

  # push changes to db
  Change.insert(db_changes)


if __name__ == '__main__':
  print "starting QIRA middleware"
  objdump_out = subprocess.Popen(
    ["objdump", "-d", "/tmp/qira_binary"],
    stdout = subprocess.PIPE).communicate()[0]
  for line in objdump_out.split("\n"):
    line = line.split("\t")
    if len(line) == 3:
      addr = int(line[0].strip(" :"), 16)
      instructions[addr] = line[2]
      #print hex(addr), line[2]
    else:
      # could get names here too, but maybe useless for now
      #print line
      pass
  print "objdump parse got",len(instructions),"instructions"

  # connect to db, set up collections, and drop
  db = MongoClient('localhost', 3001).meteor
  Change = db.change
  Pmaps = db.pmaps
  Change.drop()
  Pmaps.drop()
  print "dropped old databases"

  # run loop run
  changes_committed = 1
  while 1:
    time.sleep(0.05)
    max_changes = get_log_length(LOGFILE)
    if changes_committed < max_changes:
      process(read_log(LOGFILE, changes_committed))

