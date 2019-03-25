#!/usr/bin/env python3
from __future__ import print_function
import os
import sys
import mmap
import struct
import ctypes

import cle
from unicorn import *
from unicorn.x86_const import *
from capstone import *

# we need a unicorn
mu = Uc(UC_ARCH_X86, UC_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

# load mmap function
libc = ctypes.cdll.LoadLibrary(None)

_ptrace = libc.ptrace
_ptrace.restype = ctypes.c_long
_ptrace.argtypes = (ctypes.c_int, ctypes.c_long,
                    ctypes.c_void_p, ctypes.c_void_p)

_mmap = libc.mmap
_mmap.restype = ctypes.c_void_p
_mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t,
                          ctypes.c_int, ctypes.c_int,
                          ctypes.c_int, ctypes.c_size_t)

def wrapped_mem_map(address, size):
  fd = os.open("/dev/shm/twilight-%x-%x" % (address, size), os.O_CREAT | os.O_RDWR)
  os.ftruncate(fd, size)
  ptr = _mmap(None, size,
              mmap.PROT_READ | mmap.PROT_WRITE,
              mmap.MAP_SHARED,
              fd, 0)
  mu.mem_map_ptr(address, size, UC_PROT_ALL, ptr)

# load the stack into unicorn
# https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html
STACK_TOP = 0xaaa0000
STACK_SIZE = 0x8000
wrapped_mem_map(STACK_TOP-STACK_SIZE, STACK_SIZE)  # fake stack
argv = sys.argv[1]
stack = "/lib/x86_64-linux-gnu/ld-2.23.so\x00"+argv+"\x00"
stack = struct.pack("QQQQQQ",
   # argc
   2,
   # argv
   STACK_TOP-len(stack)+stack.index("/lib/x86_64-linux-gnu/ld-2.23.so"),
   STACK_TOP-len(stack)+stack.index(argv),
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

  wrapped_mem_map(vaddr, memsize)
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

# start the <<<shell process>>>
PTRACE_TRACEME = 0
PTRACE_PEEKUSER = 3
child = os.fork()
if child == 0:
  traceme = _ptrace(PTRACE_TRACEME, 0, None, None)
  os.execl("/bin/true", "true")
print("wait:", os.wait(), child)

os.system("cat /proc/%d/maps" % child)

# run
print("emulation started")
mu.emu_start(obj.entry, 0)

