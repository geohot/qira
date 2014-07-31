import qira_config
import os
import sys
from hashlib import sha1
basedir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(basedir+"/../cda")

import struct
import qiradb

PPCREGS = ([], 4, True)
for i in range(32):
  PPCREGS[0].append("r"+str(i))

ARMREGS = (['R0','R1','R2','R3','R4','R5','R6','R7','R8','R9','R10','R11','R12','SP','LR','PC'], 4, False)
X86REGS = (['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP'], 4, False)
X64REGS = (['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', 'RIP'], 8, False)

def cachewrap(cachedir, cachename, cachegen):
  #import json
  import pickle as json
  try:
    os.mkdir(cachedir)
  except:
    pass
  cachename = cachedir + "/" + cachename
  if os.path.isfile(cachename):
    dat = json.load(open(cachename))
    print "read cache",cachename
  else:
    print "cache",cachename,"not found, generating"
    dat = cachegen()
    if dat == None:
      return None
    f = open(cachename, "wb")
    json.dump(dat, f)
    f.close()
    print "wrote cache",cachename
  return dat

def which(prog):
  import subprocess
  cmd = ["which", prog]
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
  res = p.stdout.readlines()
  if len(res) == 0:
    # fallback mode, look for the binary straight up
    if os.path.isfile(prog):
      return os.path.realpath(prog)
    raise Exception("binary not found")
  return os.path.realpath(res[0].strip())

# things that don't cross the fork
class Program:
  def __init__(self, prog, args):
    # create the logs dir
    try:
      os.mkdir("/tmp/qira_logs")
    except:
      pass

    # call which to match the behavior of strace and gdb
    self.program = which(prog)
    self.args = args
    self.proghash = sha1(open(prog).read()).hexdigest()
    print "*** program is",self.program,"with hash",self.proghash

    # bring this back
    if self.program != "/tmp/qira_binary":
      try:
        os.unlink("/tmp/qira_binary")
      except:
        pass
      try:
        os.symlink(os.path.realpath(self.program), "/tmp/qira_binary")
      except:
        pass

    # defaultargs for qira binary
    self.defaultargs = ["-strace", "-D", "/dev/null", "-d", "in_asm", "-singlestep"]
    if qira_config.TRACE_LIBRARIES:
      self.defaultargs.append("-tracelibraries")

    # pmaps is global, but updated by the traces
    self.instructions = {}

    # get file type
    self.fb = struct.unpack("H", open(self.program).read(0x18)[0x12:0x14])[0]   # e_machine
    qemu_dir = os.path.dirname(os.path.realpath(__file__))+"/../qemu/"

    def use_lib(arch):
      maybe_path = qemu_dir+"/../libs/"+arch+"/"
      if 'QEMU_LD_PREFIX' not in os.environ and os.path.exists(maybe_path):
        os.environ['QEMU_LD_PREFIX'] = os.path.realpath(maybe_path)
        print "**** set QEMU_LD_PREFIX to",os.environ['QEMU_LD_PREFIX']

    if self.fb == 0x28:
      progdat = open(self.program).read(0x800)
      if '/lib/ld-linux.so.3' in progdat:
        use_lib('armel')
      elif '/lib/ld-linux-armhf.so.3' in progdat:
        use_lib('armhf')
      self.tregs = ARMREGS
      self.qirabinary = qemu_dir + "qira-arm"
    elif self.fb == 0x3e:
      self.tregs = X64REGS
      self.qirabinary = qemu_dir + "qira-x86_64"
    elif self.fb == 0x03:
      self.tregs = X86REGS
      self.qirabinary = qemu_dir + "qira-i386"
    elif self.fb == 0x1400:   # big endian...
      use_lib('powerpc')
      self.tregs = PPCREGS
      self.qirabinary = qemu_dir + "qira-ppc"
    else:
      raise Exception("binary type "+hex(self.fb)+" not supported")

    self.qirabinary = os.path.realpath(self.qirabinary)
    print "**** using",self.qirabinary,"for",hex(self.fb)

    # no traces yet
    self.traces = {}

    self.getdwarf()

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
      ret[t] = [self.traces[t].db.get_minclnum(), self.traces[t].db.get_maxclnum()]
    return ret

  def get_pmaps(self):
    ret = {}
    for t in self.traces:
      pm = self.traces[t].db.get_pmaps()
      for a in pm:
        if a not in ret:
          ret[a] = pm[a]
        elif ret[a] == "memory":
          ret[a] = pm[a]
    return ret

  def add_trace(self, fn, i):
    self.traces[i] = Trace(fn, i, self.tregs[1], len(self.tregs[0]), self.tregs[2])

  def execqira(self, args=[]):
    eargs = [self.qirabinary]+self.defaultargs+args+[self.program]+self.args
    print "***",' '.join(eargs)
    os.execvp(self.qirabinary, eargs)

  def getdwarf(self):
    (self.dwarves, self.rdwarves) = ({}, {})

    if not qira_config.WITH_DWARF:
      return

    # DWARF IS STUPIDLY COMPLICATED
    def parse_dwarf():
      files = []
      dwarves = {}
      rdwarves = {}

      from elftools.elf.elffile import ELFFile
      elf = ELFFile(open(self.program))
      if not elf.has_dwarf_info():
        return (files, dwarves, rdwarves)
      filename = None
      di = elf.get_dwarf_info()
      for cu in di.iter_CUs():
        try:
          basedir = None
          # get the base directory
          for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_compile_unit":
              basedir = die.attributes['DW_AT_comp_dir'].value + "/"
          if basedir == None:
            continue
          # get the line program?
          lp = di.line_program_for_CU(cu)
          dir_index = lp['file_entry'][0].dir_index
          if dir_index > 0:
            basedir += lp['include_directory'][dir_index-1]+"/"
          # now we have the filename
          filename = basedir + lp['file_entry'][0].name
          files.append(filename)
          lines = open(filename).read().split("\n")
          print "DWARF: parsing",filename
          for entry in lp.get_entries():
            s = entry.state
            if s != None:
              #print filename, s.line, len(lines)
              dwarves[s.address] = (filename, s.line, lines[s.line-1])
              rdwarves[filename+"#"+str(s.line)] = s.address
        except Exception as e:
          print "DWARF: error on",filename,"got",e
      return (files, dwarves, rdwarves)

    (files, self.dwarves, self.rdwarves) = cachewrap("/tmp/qira_dwarfcaches", self.proghash, parse_dwarf)

    # cda
    if not qira_config.WITH_CDA:
      return

    def parse_cda():
      import cachegen
      return cachegen.parse_files(files)

    self.cda = cachewrap("/tmp/qira_cdacaches", self.proghash, parse_cda)


class Trace:
  def __init__(self, fn, forknum, r1, r2, r3):
    self.forknum = forknum
    self.db = qiradb.Trace(fn, forknum, r1, r2, r3)
    self.fetch_base_memory()

  def fetch_base_memory(self):
    self.base_memory = {}
    try:
      f = open("/tmp/qira_logs/"+str(self.forknum)+"_base")
    except:
      # done
      return

    for ln in f.read().split("\n"):
      ln = ln.split(" ")
      if len(ln) < 3:
        continue
      (ss, se) = ln[0].split("-")
      ss = int(ss, 16)
      se = int(se, 16)
      offset = int(ln[1], 16)
      fn = ' '.join(ln[2:])

      try:
        f = open(fn)
      except:
        continue
      f.seek(offset)
      dat = f.read(se-ss)
      self.base_memory[(ss, se)] = dat
      f.close()


