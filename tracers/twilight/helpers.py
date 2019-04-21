import ctypes

# load ptrace and mmap function
libc = ctypes.cdll.LoadLibrary(None)

os_ptrace = libc.ptrace
os_ptrace.restype = ctypes.c_ulong
os_ptrace.argtypes = (ctypes.c_int, ctypes.c_long,
                      ctypes.c_void_p, ctypes.c_void_p)

os_mmap = libc.mmap
os_mmap.restype = ctypes.c_void_p
os_mmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t,
                          ctypes.c_int, ctypes.c_int,
                          ctypes.c_int, ctypes.c_size_t)

regtype = ctypes.c_long
class Regs(ctypes.Structure):
  _fields_ = [('r15', regtype),
              ('r14', regtype),
              ('r13', regtype),
              ('r12', regtype),
              ('rbp', regtype),
              ('rbx', regtype),
              ('r11', regtype),
              ('r10', regtype),
              ('r9', regtype),
              ('r8', regtype),
              ('rax', regtype),
              ('rcx', regtype),
              ('rdx', regtype),
              ('rsi', regtype),
              ('rdi', regtype),
              ('orig_rax', regtype),
              ('rip', regtype),
              ('cs', regtype),
              ('eflags', regtype),
              ('rsp', regtype),
              ('ss', regtype),
              ('fs_base', regtype),
              ('gs_base', regtype),
              ('ds', regtype),
              ('es', regtype),
              ('fs', regtype),
              ('gs', regtype)]

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SYSCALL = 24

