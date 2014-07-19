import qira_binary
import qira_log
import qira_memory
from collections import defaultdict
import os
import sys

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

    # if the program changed
    # BUG: if the program changes but the path doesn't
    """
    if prog != os.path.realpath("/tmp/qira_binary"):
      print "*** deleting old runs because binary changed"
      self.delete_old_runs()
    """

    # probably always good to do except in development of middleware
    self.delete_old_runs()

    # create the binary symlink
    try:
      os.unlink("/tmp/qira_binary")
    except:
      pass
    os.symlink(prog, "/tmp/qira_binary")

    # pmaps is global, but updated by the traces
    self.pmaps = {}
    self.instructions = qira_binary.objdump_binary(prog)
    self.basemem = qira_memory.Memory()

    # debug
    """
    sys.stdout.write("committing base memory..."); sys.stdout.flush()
    qira_binary.mem_commit_base_binary(prog, self.basemem)
    print "done"
    """

    # get file type
    fb = qira_binary.file_binary(prog)
    if 'ARM' in fb:
      self.tregs = ARMREGS
      self.qirabinary = "qira-arm"
    elif 'x86-64' in fb:
      self.tregs = X64REGS
      self.qirabinary = "qira-x86_64"
    else:
      self.tregs = X86REGS
      self.qirabinary = "qira-i386"

    # no traces yet
    self.traces = {}

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
    self.mem = self.program.basemem.copy()
    self.minclnum = -1
    self.maxclnum = 1

    self.changes_committed = 1

    # python db has two indexes
    # pydb_addr:  (addr, type) -> [clnums]
    # pydb_clnum: (clnum, type) -> [changes]
    self.pydb_addr = defaultdict(list)
    self.pydb_clnum = defaultdict(list)

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
      if address in self.program.instructions:
        this_change['instruction'] = self.program.instructions[address]

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

