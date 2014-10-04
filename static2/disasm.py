
# capstone is a requirement now
from capstone import *

class Destination(object):
  none = 0
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

      self.dtype = Destination.none
      if self.i.mnemonic == "call":
        self.dtype = Destination.call
      elif self.i.mnemonic == "jmp":
        self.dtype = Destination.jump
      #TODO: what about not x86?
      elif x86.X86_GRP_JUMP in self.i.groups:
        self.dtype = Destination.cjump

    #if capstone can't decode it, we're screwed
    except StopIteration:
      self.decoded = False

  def __repr__(self):
    return self.__str__()

  def __str__(self):
    if self.decoded:
      return "%s\t%s"%(self.i.mnemonic,self.i.op_str)
    return ""

  def is_jump(self):
    if not self.decoded:
      return False
    return self.dtype in [Destination.jump,Destination.cjump]

  def is_ret(self):
    if not self.decoded:
      return False
    return self.i.mnemonic == "ret"
    #TODO: what about iret? and RET isn't in the apt version of capstone
    return x86.X86_GRP_RET in self.i.groups

  def is_call(self):
    if not self.decoded:
      return False
    return self.dtype == Destination.call

  def is_ending(self):
    '''is this something which should end a basic block'''
    if not self.decoded:
      return False
    return self.is_jump() or self.is_ret()

  def is_conditional(self):
    if not self.decoded:
      return False
    return x86.X86_REG_EFLAGS in self.regs_read

  def code_follows(self):
    '''should the data after this instructino be treated as code
       note that is_ending is different, as conditional jumps still have
       code that follows'''
    if not self.decoded:
      return False
    #code follows UNLESS we are a return or an unconditional jump
    return not (self.is_ret() or self.dtype == Destination.jump)

  def size(self):
    return self.i.size if self.decoded else 0

  def dests(self):
    if not self.decoded or self.is_ret():
      return []

    dl = []
    
    if self.code_follows():
      #this piece of code leads implicitly to the next instruction
      dl.append((self.address+self.size(),Destination.implicit)) 


    if self.is_jump() or self.is_call():
      #if we take a PTR and not a MEM operand (TODO: better support for MEM operands)
      if (self.i.operands[0].value.reg) and (self.i.operands[0].value.mem.disp == 0):
        dl.append((self.i.operands[0].value.imm,self.dtype)) #the target of the jump/call

    return dl