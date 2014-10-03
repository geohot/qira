
# capstone is a requirement now
from capstone import *

class DESTTYPE(object):
  cjump = 1
  jump = 2
  call = 3
  implicit = 4

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
      self.decoded = True
      self.regs_read = self.i.regs_read
      self.regs_write = self.i.regs_write
    except StopIteration:
      self.decoded = False

  def __str__(self):
    if self.decoded:
      return "%s\t%s"%(self.i.mnemonic,self.i.op_str)
    return ""

  def is_jump(self):
    #TODO: what about not x86?
    if self.decoded:
      return x86.X86_GRP_JUMP in self.i.groups
    return False

  def is_ret(self):
    if self.decoded:
      return self.i.mnemonic == "ret"
    return False
    #TODO: what about iret? and RET isn't in the apt version of capstone
    return x86.X86_GRP_RET in self.i.groups

  def is_call(self):
    if self.decoded:
      return self.i.mnemonic == "call"
    return False

  def is_ending(self):
    if self.decoded:
      '''is this something which should end a basic block'''
      return self.is_jump() or self.is_ret()
    return False

  def size(self):
    return self.i.size if self.decoded else 0

  def dests(self):
    if self.decoded and not self.is_ret():
      dl = []
      if self.is_jump() or self.is_call():
        if (self.i.operands[0].value.reg) and (self.i.operands[0].value.mem.disp == 0):
          if self.i.mnemonic == "jmp":
            dtype = DESTTYPE.jump
          else:
            #the next instruction after this one
            dl.append((self.address+self.size(),DESTTYPE.implicit))
            if self.i.mnemonic == "call":
              dtype = DESTTYPE.call
            else:
              dtype = DESTTYPE.cjump
          dl.append((self.i.operands[0].value.imm,dtype)) #the target of the jump/call

        else:
          dl.append((self.address+self.size(),DESTTYPE.implicit))
        return dl
      else:
       return [(self.address+self.size(),DESTTYPE.implicit)]
    return []

