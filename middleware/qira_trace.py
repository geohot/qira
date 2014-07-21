import qira_log
import qira_memory
import threading
import struct
from collections import defaultdict
import os
import sys
import time

ARMREGS = (['R0','R1','R2','R3','R4','R5','R6','R7','R8','R9','R10','R11','R12','SP','LR','PC'], 4)
X86REGS = (['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP'], 4)
X64REGS = (['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', 'RIP'], 8)

# things that don't cross the fork
class Program:
  def __init__(self, prog):
    # create the logs dir
    try:
      os.mkdir("/tmp/qira_logs")
    except:
      pass

    # probably always good to do except in development of middleware
    print "*** deleting old runs"
    self.delete_old_runs()

    # getting asm from qemu
    self.create_asm_file()

    # create the binary symlink
    try:
      os.unlink("/tmp/qira_binary")
    except:
      pass
    os.symlink(prog, "/tmp/qira_binary")

    # pmaps is global, but updated by the traces
    self.pmaps = {}
    #self.instructions = qira_binary.objdump_binary(prog)
    self.instructions = {}
    """
    self.basemem = qira_memory.Memory()

    print "committing base memory..."
    qira_binary.mem_commit_base_binary(prog, self.basemem)
    """

    # get file type
    #self.fb = qira_binary.file_binary(prog)
    self.fb = struct.unpack("H", open(prog).read(0x18)[0x12:0x14])[0]
    print "e_machine is",hex(self.fb)
    if self.fb == 0x28:
      self.tregs = ARMREGS
      self.qirabinary = "qira-arm"
    elif self.fb == 0x3e:
      self.tregs = X64REGS
      self.qirabinary = "qira-x86_64"
    elif self.fb == 0x03:
      self.tregs = X86REGS
      self.qirabinary = "qira-i386"
    else:
      print "BINARY TYPE NOT SUPPORTED"

    # no traces yet
    self.traces = {}

  def create_asm_file(self):
    try:
      os.unlink("/tmp/qira_asm")
    except:
      pass
    open("/tmp/qira_asm", "a").close()
    self.qira_asm_file = open("/tmp/qira_asm", "r")

  def read_asm_file(self):
    dat = self.qira_asm_file.read()
    if len(dat) == 0:
      return
    cnt = 0
    for d in dat.split("\n"):
      if len(d) == 0:
        continue
      # hacks
      addr = int(d.split(" ")[0].strip(":"), 16)
      #print repr(d)
      if self.fb == 0x28:   # ARM
        inst = d[d.rfind("  ")+2:]
      else:
        inst = d[d.find(":")+3:]
      self.instructions[addr] = inst
      cnt += 1
      #print addr, inst
    sys.stdout.write("%d..." % cnt); sys.stdout.flush()

  def delete_old_runs(self):
    # delete the logs
    for i in os.listdir("/tmp/qira_logs"):
      os.unlink("/tmp/qira_logs/"+i)

  def get_maxclnum(self):
    ret = {}
    for t in self.traces:
      ret[t] = [self.traces[t].minclnum, self.traces[t].maxclnum]
    return ret

class Trace:
  def __init__(self, program, forknum):
    self.program = program
    self.program.traces[forknum] = self
    self.forknum = forknum
    self.reset()

  def reset(self):
    self.regs = qira_memory.Memory()
    self.mem = qira_memory.Memory()
    #self.mem = self.program.basemem.copy()
    self.minclnum = -1
    self.maxclnum = 1

    self.changes_committed = 1

    # python db has two indexes
    # pydb_addr:  (addr, type) -> [clnums]
    # pydb_clnum: (clnum, type) -> [changes]
    self.pydb_addr = defaultdict(list)
    self.pydb_clnum = defaultdict(list)

    for ln in open("/tmp/qira_logs/"+str(self.forknum)+"_base").read().split("\n"):
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
      print hex(ss)+"-"+hex(se), offset, fn

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


