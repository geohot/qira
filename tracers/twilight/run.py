#!/usr/bin/env python3
from __future__ import print_function
import sys
import cle
import struct
from unicorn import *
from unicorn.x86_const import *
from capstone import *

# we need a unicorn
mu = Uc(UC_ARCH_X86, UC_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

# load the stack into unicorn
# https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html
STACK_TOP = 0xaaa0000
mu.mem_map(STACK_TOP-0x1000, 0x1000)  # fake stack
stack = "/lib/x86_64-linux-gnu/ld-2.23.so\x00/bin/cat\x00"
stack = struct.pack("QQQQQQ",
   # argc
   2,
   # argv
   STACK_TOP-len(stack)+stack.index("/lib/x86_64-linux-gnu/ld-2.23.so"),
   STACK_TOP-len(stack)+stack.index("/bin/cat"),
   0,
   # envp
   0,
   # ELF Auxiliary Table
   0
   )
mu.mem_write(STACK_TOP-len(stack), stack)
mu.reg_write(UC_X86_REG_RSP, STACK_TOP-len(stack))

# load the dynamic loader, so meta
ld = cle.Loader("/lib/x86_64-linux-gnu/ld-2.23.so")
obj = ld.main_object
print("entry point: %x" % obj.entry)

for seg in obj.segments:
  print("%x sz %x -> %x sz %x" % (seg.offset, seg.filesize, seg.vaddr, seg.memsize))
  vaddr = seg.vaddr
  memsize = seg.memsize + vaddr%0x1000
  vaddr -= vaddr%0x1000
  memsize += 0xFFF
  memsize -= memsize%0x1000

  mu.mem_map(vaddr, memsize)
  mu.mem_write(seg.vaddr, ld.memory.load(seg.vaddr, seg.memsize))
print("loaded file")

# for debugging
def hook_code(uc, address, size, user_data):
  #print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
  for i in md.disasm(mu.mem_read(address, size), address):
    print("  0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
#mu.hook_add(UC_HOOK_CODE, hook_code)

# hook interrupts for syscall
import angr.procedures.definitions.linux_kernel as lk 
def hook_syscall(mu, user_data):
  rax = mu.reg_read(UC_X86_REG_RAX)
  rdi = mu.reg_read(UC_X86_REG_RDI)
  rsi = mu.reg_read(UC_X86_REG_RSI)

  print("syscall %4d : %-20s -- %x %x" %
    (rax, lk.lib.syscall_number_mapping['amd64'][rax], rdi, rsi))
  return False

mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

# run
mu.emu_start(obj.entry, 0)

