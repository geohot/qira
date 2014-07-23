import os
import sys
import struct

ARMREGS = (['R0','R1','R2','R3','R4','R5','R6','R7','R8','R9','R10','R11','R12','SP','LR','PC'], 4)
X86REGS = (['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP'], 4)
X64REGS = (['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', 'RIP'], 8)

# things that don't cross the fork
class Program:
  def __init__(self, prog, args):
    # create the logs dir
    try:
      os.mkdir("/tmp/qira_logs")
    except:
      pass

    # pmaps is global, but updated by the traces
    self.instructions = {}

    self.program = prog
    self.args = args

    # get file type
    #self.fb = qira_binary.file_binary(prog)
    self.fb = struct.unpack("H", open(prog).read(0x18)[0x12:0x14])[0]
    qemu_dir = os.path.dirname(os.path.realpath(__file__))+"/../qemu/"
    if self.fb == 0x28:
      if 'QEMU_LD_PREFIX' not in os.environ:
        os.environ['QEMU_LD_PREFIX'] = os.path.realpath(qemu_dir+"/../libs/armhf/")
        print "**** set QEMU_LD_PREFIX to",os.environ['QEMU_LD_PREFIX']
      self.tregs = ARMREGS
      self.qirabinary = qemu_dir + "qira-arm"
    elif self.fb == 0x3e:
      self.tregs = X64REGS
      self.qirabinary = qemu_dir + "qira-x86_64"
    elif self.fb == 0x03:
      self.tregs = X86REGS
      self.qirabinary = qemu_dir + "qira-i386"
    else:
      raise Exception("binary type not supported")

    print "**** using",self.qirabinary,"for",hex(self.fb)

    # no traces yet
    self.traces = {}

  def clear(self):
    # probably always good to do except in development of middleware
    print "*** deleting old runs"
    self.delete_old_runs()

    # getting asm from qemu
    self.create_asm_file()

  def create_asm_file(self):
    try:
      os.unlink("/tmp/qira_asm")
    except:
      pass
    open("/tmp/qira_asm", "a").close()
    self.qira_asm_file = open("/tmp/qira_asm", "r")

  def read_asm_file(self):
    dat = self.qira_asm_file.read()
    if len(dat) == 0:
      return
    cnt = 0
    for d in dat.split("\n"):
      if len(d) == 0:
        continue
      # hacks
      addr = int(d.split(" ")[0].strip(":"), 16)
      #print repr(d)
      if self.fb == 0x28:   # ARM
        inst = d[d.rfind("  ")+2:]
      else:
        inst = d[d.find(":")+3:]
      self.instructions[addr] = inst
      cnt += 1
      #print addr, inst
    #sys.stdout.write("%d..." % cnt); sys.stdout.flush()

  def delete_old_runs(self):
    # delete the logs
    for i in os.listdir("/tmp/qira_logs"):
      os.unlink("/tmp/qira_logs/"+i)
      
  def get_maxclnum(self):
    ret = {}
    for t in self.traces:
      ret[t] = [self.traces[t].get_minclnum(), self.traces[t].get_maxclnum()]
    return ret

  def get_pmaps(self):
    ret = {}
    for t in self.traces:
      pm = self.traces[t].get_pmaps()
      for a in pm:
        if a not in ret:
          ret[a] = pm[a]
        elif ret[a] == "memory":
          ret[a] = pm[a]
    return ret

