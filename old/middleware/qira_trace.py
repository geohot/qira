import qiradb
import threading
import struct
from collections import defaultdict
import os
import sys
import time

class Trace:
  def __init__(self, program, forknum):
    self.logfile = open("/tmp/qira_logs/"+str(forknum))

    self.program = program
    self.program.traces[forknum] = self

    self.forknum = forknum

    self.reset()

  def reset(self):
    self.regs = qira_memory.Memory()
    self.mem = qira_memory.Memory()

    self.minclnum = -1
    self.maxclnum = 1

    self.changes_committed = 1

    # python db has two indexes
    # pydb_addr:  (addr, type) -> [clnums]
    # pydb_clnum: (clnum, type) -> [changes]
    self.pydb_addr = defaultdict(list)
    self.pydb_clnum = defaultdict(list)

    try:
      f = open("/tmp/qira_logs/"+str(self.forknum)+"_base")
    except:
      # done
      return

    for ln in f.read().split("\n"):
      ln = ln.split(" ")
      if len(ln) < 3:
        continue
      (ss, se) = ln[0].split("-")
      ss = int(ss, 16)
      se = int(se, 16)
      offset = int(ln[1], 16)
      fn = ' '.join(ln[2:])

      try:
        f = open(fn)
      except:
        continue
      f.seek(offset)
      dat = f.read(se-ss)
      self.mem.bcommit(ss, dat)
      f.close()
      #print hex(ss)+"-"+hex(se), offset, fn

  def poll(self):
    max_changes = qira_log.get_log_length(self.logfile)
    if self.changes_committed < max_changes:
      total_changes = max_changes - self.changes_committed
      # clamping to keep the server responsive
      # python threads really aren't very good
      if total_changes > 30000:
        total_changes = 30000
      if self.changes_committed > 1000000:
        # clamped
        return False
      sys.stdout.write("on %d going from %d to %d..." % (self.forknum, self.changes_committed,max_changes))
      sys.stdout.flush()
      log = qira_log.read_log(self.logfile, self.changes_committed, total_changes)
      sys.stdout.write("read..."); sys.stdout.flush()
      self.process(log)
      print "done", self.maxclnum
      self.changes_committed += total_changes
      return True
    return False


  # *** HANDLER FOR qira_log ***
  def process(self, log_entries):
    for (address, data, clnum, flags) in log_entries:
      if self.minclnum == -1 or clnum < self.minclnum:
        self.minclnum = clnum
      if clnum > self.maxclnum:
        self.maxclnum = clnum

      # construct this_change
      pytype = qira_log.flag_to_type(flags)
      this_change = {'address': address, 'type': pytype,
          'size': flags&qira_log.SIZE_MASK, 'clnum': clnum, 'data': data}
      """
      if address in self.program.instructions:
        this_change['instruction'] = self.program.instructions[address]
      """

      # update python database
      self.pydb_addr[(address, pytype)].append(clnum)
      self.pydb_clnum[(clnum, pytype)].append(this_change)

      # update local regs and mem database
      # this is somewhat slow...
      if flags & qira_log.IS_WRITE and flags & qira_log.IS_MEM:
        size = flags & qira_log.SIZE_MASK
        # support big endian
        for i in range(0, size/8):
          self.mem.commit(clnum, address+i, data & 0xFF)
          data >>= 8
      elif flags & qira_log.IS_WRITE:
        size = flags & qira_log.SIZE_MASK
        # support big endian
        self.regs.commit(clnum, address, data)

      # for Pmaps
      # shouldn't really send this each time, but it should be smaller anyway
      page_base = (address>>12)<<12
      if flags & qira_log.IS_MEM and page_base not in self.program.pmaps:
        self.program.pmaps[page_base] = "memory"
      if flags & qira_log.IS_START:
        self.program.pmaps[page_base] = "instruction"
    # *** FOR LOOP END ***
    self.program.read_asm_file()


