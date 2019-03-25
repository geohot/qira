#!/usr/bin/env python3
from __future__ import print_function
import os
import sys
import mmap
import struct
import ctypes
from hexdump import hexdump
from helpers import *

# start the <<<shell process>>>
child = os.fork()
if child == 0:
  traceme = os_ptrace(PTRACE_TRACEME, 0, None, None)
  os.execl("/bin/true", "true")
print("wait:", os.wait(), child)
regs = Regs()
assert os_ptrace(PTRACE_GETREGS, child, None, ctypes.pointer(regs)) == 0
stub_location = regs.rip
print("stub:%x" % stub_location)
assert os_ptrace(PTRACE_POKETEXT, child, stub_location, 0xf4050f) == 0

def pmaps():
  print(open("/proc/%d/maps" % child).read().strip())

def shell_syscall(num, args, rip=stub_location):
  regs = Regs()
  assert os_ptrace(PTRACE_GETREGS, child, None, ctypes.pointer(regs)) == 0
  regs.rax = num
  if len(args) > 0:
    regs.rdi = args[0]
  if len(args) > 1:
    regs.rsi = args[1]
  if len(args) > 2:
    regs.rdx = args[2]
  if len(args) > 3:
    regs.r10 = args[3]
  if len(args) > 4:
    regs.r8 = args[4]
  if len(args) > 5:
    regs.r9 = args[5]
  regs.rip = rip
  assert os_ptrace(PTRACE_SETREGS, child, None, ctypes.pointer(regs)) == 0

  # run syscall stub
  assert os_ptrace(PTRACE_SINGLESTEP, child, None, None) == 0
  _, wait_reason = os.wait()
  if wait_reason != 0x57f:
    print("shell process exited (num:%d rip:%x) : %x" % (num, rip, wait_reason))
    exit(0)

  # return rax
  assert os_ptrace(PTRACE_GETREGS, child, None, ctypes.pointer(regs)) == 0
  return regs.rax

def shell_unmap(addr, endaddr):
  ret = shell_syscall(11, [addr, endaddr-addr])
  #print("unmapping 0x%x-0x%x : %d" % (addr, endaddr, ret))

def shell_map_file(addr, name, size, prot, offset=0):
  # copy name into shell process
  name += b"\x00"*(8-len(name)%8)
  for i in range(0, len(name), 8):
    dat = struct.unpack("Q", name[i:i+8])[0]
    assert os_ptrace(PTRACE_POKETEXT, child, stub_location+8+i, dat) == 0

  # open file
  fd = shell_syscall(2, [stub_location+8, os.O_RDWR, 0])
  assert shell_syscall(9, [addr, size, prot, mmap.MAP_SHARED, fd, offset])
  shell_syscall(3, [fd])

segs = [[int("0x"+y, 16) for y in x.split(" ")[0].split("-")] \
        for x in open("/proc/%d/maps" % child).read().strip().split("\n")]
stub_segs = filter(lambda x: (x[0] <= stub_location and stub_location < x[1]), segs)
ok_segs = filter(lambda x: not 
  ((x[0] <= stub_location and stub_location < x[1]) or 
    x[0] == 0xffffffffff600000), segs) 
[shell_unmap(*x) for x in ok_segs]
#pmaps()
#exit(0)

# loading time
import cle
from unicorn import *
from unicorn.x86_const import *
from capstone import *

# we need a unicorn
mu = Uc(UC_ARCH_X86, UC_MODE_64)
md = Cs(CS_ARCH_X86, CS_MODE_64)

"""
# confirm syscall stub
regs = Regs()
assert os_ptrace(PTRACE_GETREGS, child, None, ctypes.pointer(regs)) == 0
print(hex(regs.rip))
print(hex(regs.rax))
ret = os_ptrace(PTRACE_PEEKTEXT, child, stub_location, None)
print(ret)
for i in md.disasm(struct.pack("Q", ret), stub_location):
  print("  0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
"""

maps = []

def wrapped_mem_map(address, size, fd=None, prot=mmap.PROT_READ | mmap.PROT_WRITE):
  dsize = size + 0xfff
  dsize &= ~0xfff

  for am,asm,nm,ptr in maps:
    if am <= address and address < (am+asm):
      # reuse
      print("reuse %s" % nm)
      shell_map_file(address, nm, size, 7, offset=address-am)
      return

  nm = b"/dev/shm/twilight-%x-%x" % (address, dsize)
  fd = os.open(nm, os.O_CREAT | os.O_RDWR)
  os.ftruncate(fd, dsize)

  # mmap in shell process
  shell_map_file(address, nm, size, 7)

  # mmap locally
  ptr = os_mmap(None, size,
                mmap.PROT_READ | mmap.PROT_WRITE,
                mmap.MAP_SHARED,
                fd, 0)
  print("mapping %x sz %x fd %d at %x" % (address, size, fd, ptr))
  mu.mem_map_ptr(address, dsize, UC_PROT_ALL, ptr)
  maps.append([address, dsize, nm, ptr])

# load the stack into unicorn
# https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html
STACK_TOP = 0xaaa0000
STACK_SIZE = 0x8000
wrapped_mem_map(STACK_TOP-STACK_SIZE, STACK_SIZE)  # fake stack
argv = sys.argv[1].encode('utf-8')
stack = b"/lib/x86_64-linux-gnu/ld-2.23.so\x00"+argv+b"\x00"
stack = struct.pack("QQQQQQ",
   # argc
   2,
   # argv
   STACK_TOP-len(stack)+stack.index(b"/lib/x86_64-linux-gnu/ld-2.23.so"),
   STACK_TOP-len(stack)+stack.index(argv),
   0,
   # envp
   0,
   # ELF Auxiliary Table
   0
   ) + stack
#hexdump(stack)
mu.mem_write(STACK_TOP-len(stack), stack)
mu.reg_write(UC_X86_REG_RSP, STACK_TOP-len(stack))

# load the dynamic loader, so meta
ld = cle.Loader("/lib/x86_64-linux-gnu/ld-2.23.so")
obj = ld.main_object
print("entry point: %x" % obj.entry)

# real ish
OFFSET = 0x4000000000 - 0x400000
#OFFSET = 0

for seg in obj.segments:
  print("%x sz %x -> %x sz %x" % (seg.offset, seg.filesize, seg.vaddr, seg.memsize))
  vaddr = seg.vaddr
  memsize = seg.memsize + vaddr%0x1000
  vaddr -= vaddr%0x1000
  memsize += 0xFFF
  memsize -= memsize%0x1000

  wrapped_mem_map(OFFSET + vaddr, memsize)
  mu.mem_write(OFFSET + seg.vaddr, ld.memory.load(seg.vaddr, seg.memsize))
print("loaded file")

# hook interrupts for syscall
import angr.procedures.definitions.linux_kernel as lk 
def hook_syscall(mu, user_data):
  num = mu.reg_read(UC_X86_REG_RAX)
  rargs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
           UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9]
  args = [mu.reg_read(x) for x in rargs]
  rip = mu.reg_read(UC_X86_REG_RIP)

  print("%8x syscall %4d : %-20s %x %x %x" %
    (rip, num, lk.lib.syscall_number_mapping['amd64'][num], args[0], args[1], args[2]), end=" ")

  if num == 231 or num == 60:
    print("fake exit(%d)" % args[0])
    return

  # do syscall in shell process 
  ret = shell_syscall(num, args, rip)
  mu.reg_write(UC_X86_REG_RAX, ret)

  if num == 9:
    #pmaps()
    #os.system("ls -l /proc/%d/map_files" % child)
    dat = None
    for x in os.listdir("/proc/%d/map_files" % child):
      if "%x-"%ret in x:
        size = int("0x"+x.split("-")[1], 16) - ret
        nm = "/proc/%d/map_files/%s" % (child, x)
        nm = os.path.realpath(nm)
        print("\nopening %s" % nm)
        with open(nm, "rb") as f:
          f.seek(args[-1])
          dat = f.read(size)
          break
        #if args[2] & mmap.PROT_WRITE:
        #else:
        #  fd = os.open(nm, os.O_RDONLY)
        #  wrapped_mem_map(ret, size, fd, prot=args[2])
        #break

    # it's not a file, anon mmap is good
    shell_unmap(ret, ret+args[1])
    wrapped_mem_map(ret, args[1])
    if dat is not None:
      print("%x %x" % (ret, len(dat)))
      mu.mem_write(ret, dat)

  print("    returned %x" % ret)

mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

# confirm munmap and mmap
#[shell_unmap(*x) for x in stub_segs]
print("shell process")
pmaps()

# for debugging
def hook_code(uc, address, size, user_data):
  #print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
  for i in md.disasm(mu.mem_read(address, size), address):
    print("  0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
#mu.hook_add(UC_HOOK_CODE, hook_code)

# QIRA tracer
qlog_base = open("/tmp/qira_logs/1_base", "w")
qlog_base.write("%016X-%016X %X /lib/x86_64-linux-gnu/ld-2.23.so\n" % (OFFSET + 0x400000, OFFSET + 0x428000, 0))
qlog_base.close()
qlog = open("/tmp/qira_logs/1", "wb")
qlog.write(open("/tmp/qira_logs/0", "rb").read(0x18))

regs = ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", 'RIP']
ucregs = [eval("UC_X86_REG_"+x) for x in regs]
IS_VALID = 0x80000000
IS_WRITE = 0x40000000
IS_MEM = 0x20000000
IS_START = 0x10000000
IS_SYSCALL = 0x08000000
clnum = 0
def hook_code_qlog(uc, address, size, user_data):
  global clnum
  clnum += 1
  aa = [mu.reg_read(x) for x in ucregs]
  dat = struct.pack("QQII", aa[-1], 0, clnum, IS_VALID | IS_START)
  qlog.write(dat)
  for i in range(0, len(regs)):
    dat = struct.pack("QQII", i*8, aa[i], clnum, IS_VALID | IS_WRITE)
    qlog.write(dat)
#mu.hook_add(UC_HOOK_CODE, hook_code_qlog)

# run
print("emulation started")
try:
  mu.emu_start(OFFSET + obj.entry, 0)
except unicorn.UcError:
  print("issue")

pmaps()
print("exiting")
qlog.close()

