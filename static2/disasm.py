
# capstone is a requirement now
from capstone import *

class disasm(object):
  """one disassembled instruction"""
  def __init__(self, raw, address, arch="i386"):
    self.raw = raw
    self.address = address
    if arch == "i386":
      self.md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == "x86-64":
      self.md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "thumb":
      self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif arch == "arm":
      self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch == "aarch64":
      self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == "ppc":
      self.md = Cs(CS_ARCH_PPC, CS_MODE_32)
    else:
      raise Exception('arch not supported by capstone')
    self.md.detail = True
    try:
      self.i = self.md.disasm(self.raw, self.address).next()
    except StopIteration:
      return None

    self.regs_read = self.i.regs_read
    self.regs_write = self.i.regs_write

  def __str__(self):
    return "%s\t%s"%(self.i.mnemonic,self.i.op_str)

  def is_jump(self):
    return x86.X86_GRP_JUMP in self.i.groups

  def is_ret(self):
    #TODO: what about iret?
    return x86.X86_GRP_RET in self.i.groups

  def is_ending(self):
    '''is this something which should end a basic block'''
    return self.is_jump() or self.is_ret()

  def size(self):
    return self.i.size