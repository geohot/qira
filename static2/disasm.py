
# capstone is a requirement now
from capstone import *
import capstone.arm as arm

# The pair (INSTYPE, DESTTYPE) tells us the type of instruction, as well
# as the type of destination address.

# ITYPE tells us the type of instruction we are dealing with
class ITYPE(object):
  seq = 0    # sequential instruction
  cjump = 1  # Conditional branch
  jump = 2   # unconditional branch
  call = 3   # call branch
  ret = 5    # return branch

# TTYPE is the target operand type. We want to distinguish sequential, indirect, immediates, etc.
# Hmm. What I really want is a sum type here:
# type ttype = seq of addresss | immediate of address | other
class TTYPE(object):
  seq = 0         # the target is the next seq. instruction
  immediate = 1   # the target is an immediate value.
  ret = 2         # ret target (on stack?, bl? these are questions we could answer with BAP!)
  other = 3       # Any other target type, e.g., an indirect jump target



# An assembly instruction should carry:
#  - Its address addr
#  - Its architecture (for now, so we can reason about it based on the ISA)
#  - The ITYPE for the instruction.
#  - The set of successor targets TTYPE

# This allows a user for the disasm instruction to group an instruction by its type,
# as well as to find the successor addresses as best as can be determined locally.

class disasm(object):
  """one disassembled instruction"""
  def __init__(self, raw, address, arch="i386"):
    self.raw = raw
    self.address = address
    self.succ = set() # no successors
    self.itype = ITYPE.seq  # default is a sequential instruction
    if arch == "i386":
      self.md = Cs(CS_ARCH_X86, CS_MODE_32)
      self.arch = CS_ARCH_X86.i386
    elif arch == "x86-64":
      self.md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "thumb":
      self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif arch == "arm":
      self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
      self.arch = CS_ARCH_ARM
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

      # ARM-local code. Could be a subclass.
      if(self.arch == CS_ARCH_ARM):
          # first set type of instruction
          if(self.i.mnemonic == "bl"):
            self.itype = ITYPE.call
          elif(self.i.mnemonic == "b"):
            self.itype = ITYPE.jump
          elif(arm.ARM_GRP_JUMP in self.i.groups):
            self.itype = ITYPE.cjump
          # then calculate initial control flow targets (under)approx.
          if(self.itype in [ITYPE.call, ITYPE.jump, ITYPE.cjump]):
            if(self.i.operands[0].type == arm.ARM_OP_IMM):
              t = self.i.operands[0].value.imm + self.address + 0x8
              self.succ.add((t, TTYPE.immediate))
          # sequential instructions and cjumps have the next instruction
          # as a potential target. Note here we treat calls as "sequential"
          if(self.itype in [ITYPE.cjump, ITYPE.seq, ITYPE.call]):
            # fallthrough address is also a target for seq and cjumps
            self.succ.add((self.address+self.size(), TTYPE.seq))

      if(self.arch == CS_ARCH_X86):
        if self.i.mnemonic == "call":
          self.dtype = ITYPE.call
        elif self.i.mnemonic == "jmp":
          self.dtype = ITYPE.jmp
        elif self.i.mnemonic == "ret":
          self.dtype = ITYPE.ret
        elif (x86.X86_GRP_JUMP in self.i.groups):
          self.dtype = ITYPE.cjump

        if(self.dtype in [ITYPE.call, ITYPE.jump, ITYPE.cjump]):
          if(self.i.operands[0].type == x86.X86_OP_IMM):
            self.succ.add(self.i.operands[0].value.imm)
          if(self.dtype in [DESTTYPE.cjump, DESTTYPE.none]):
            self.succ.add(self.address+self.size)

    #if capstone can't decode it, we're screwed
    except StopIteration:
      self.decoded = False

  def __repr__(self):
    return self.__str__()

  def __str__(self):
    if self.decoded:
      return "%s\t%s"%(self.i.mnemonic,self.i.op_str)
    return ""

  ####   The following functions are useless! Accessors are for C++ junkies. Do not use! ######

  def is_jump(self):
    if not self.decoded:
      return False
    return self.itype in [ITYPE.jump,ITYPE.cjump]

  def is_ret(self):
    if not self.decoded:
      return False
    return self.i.mnemonic == "ret"
    #TODO: what about iret? and RET isn't in the apt version of capstone
    return x86.X86_GRP_RET in self.i.groups

  def is_call(self):
    if not self.decoded:
      return False
    return self.dtype == DESTTYPE.call

  def is_ending(self):
    '''is this something which should end a basic block'''
    if not self.decoded:
      return False
    return self.is_jump() or self.is_ret() or self.i.mnemonic == "hlt"

  def is_conditional(self):
    if not self.decoded:
      return False
    #TODO shouldn't be x86 specific
    return x86.X86_REG_EFLAGS in self.regs_read

  def code_follows(self):
    '''should the data after this instructino be treated as code
       note that is_ending is different, as conditional jumps still have
       code that follows'''
    if not self.decoded:
      return False
    #code follows UNLESS we are a return or an unconditional jump
    return not (self.is_ret() or self.dtype == DESTTYPE.jump)

  def size(self):
    return self.i.size if self.decoded else 0

  def dests(self):
    if not self.decoded: #or self.is_ret():
      return set()

    return self.succ

    # dl = []
    # #if(self.address == 0x930c):
    #   #print "HI"
    #   #pdb.set_trace()

    # if self.code_follows():
    #   #this piece of code leads implicitly to the next instruction
    #   dl.append((self.address+self.size(),DESTTYPE.implicit))


    # if self.is_jump() or self.is_call():
    #   #if we take a PTR and not a MEM or REG operand (TODO: better support for MEM operands)
    #   #TODO: shouldn't be x86 specific
    #   if (self.arch == CS_ARCH_X86 and self.i.operands[0].type == x86.X86_OP_IMM):
    #     dl.append((self.i.operands[0].value.imm,self.dtype)) #the target of the jump/call
    #   elif (self.arch == CS_ARCH_ARM and self.i.operands[0].type == arm.ARM_OP_IMM):
    #     #if self.is_call():
    #       # add in pipeline offset on arm
    #       target = self.i.operands[0].value.imm + self.i.address + 0x8
    #       dl.append((target, self.dtype))
    #     #else:
    #     #  dl.append((self.i.operands[0].value.imm, self.dtype))

    # return dl

