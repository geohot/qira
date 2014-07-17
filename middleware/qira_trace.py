from qira_log import *
from qira_binary import *
from qira_memory import *
from collections import defaultdict

X86REGS = (['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP'], 4)
X64REGS = (['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', 'RIP'], 8)

class Trace:
  def __init__(self, prog):
    # python db has two indexes
    #  types are I, r, m
    # pydb_addr:  (addr, type) -> [clnums]
    # pydb_clnum: (clnum, type) -> [changes]
    self.pmaps = {}
    self.regs = Memory()
    self.mem = Memory()
    self.maxclnum = 1
    self.pydb_addr = defaultdict(list)
    self.pydb_clnum = defaultdict(list)
    self.instructions = objdump_binary(prog)

    # get file type
    fb = file_binary(prog)
    if 'x86-64' in fb:
      self.tregs = X64REGS
    else:
      self.tregs = X86REGS

    mem_commit_base_binary(prog, self.mem)

  # *** HANDLER FOR qira_log ***
  def process(self, log_entries):
    for (address, data, clnum, flags) in log_entries:
      if clnum > self.maxclnum:
        self.maxclnum = clnum

      # construct this_change
      pytype = flag_to_type(flags)
      this_change = {'address': address, 'type': pytype,
          'size': flags&SIZE_MASK, 'clnum': clnum, 'data': data}
      if address in self.instructions:
        this_change['instruction'] = self.instructions[address]

      # update python database
      self.pydb_addr[(address, pytype)].append(clnum)
      self.pydb_clnum[(clnum, pytype)].append(this_change)

      # update local regs and mem database
      # this is somewhat slow...
      if flags & IS_WRITE and flags & IS_MEM:
        size = flags & SIZE_MASK
        # support big endian
        for i in range(0, size/8):
          self.mem.commit(clnum, address+i, data & 0xFF)
          data >>= 8
      elif flags & IS_WRITE:
        size = flags & SIZE_MASK
        # support big endian
        self.regs.commit(clnum, address, data)

      # for Pmaps
      # shouldn't really send this each time, but it should be smaller anyway
      page_base = (address>>12)<<12
      if flags & IS_MEM and page_base not in self.pmaps:
        self.pmaps[page_base] = "memory"
      if flags & IS_START:
        self.pmaps[page_base] = "instruction"
    # *** FOR LOOP END ***

