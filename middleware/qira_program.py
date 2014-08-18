from qira_base import *
import qira_config
import qira_analysis
import os
import shutil
import sys
import subprocess
from hashlib import sha1
sys.path.append(qira_config.BASEDIR+"/cda")

try:  
  from capstone import *
except:
  pass

import struct
import qiradb

# (regname, regsize, is_big_endian, arch_name)
PPCREGS = ([], 4, True, "ppc")
for i in range(32):
  PPCREGS[0].append("r"+str(i))

AARCH64REGS = (['R0','R1','R2','R3','R4','R5','R6','R7','R8','R9','R10','R11','R12','SP','LR','PC'], 8, False, "aarch64")
ARMREGS = (['R0','R1','R2','R3','R4','R5','R6','R7','R8','R9','R10','R11','R12','SP','LR','PC'], 4, False, "arm")
X86REGS = (['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP'], 4, False, "i386")
X64REGS = (['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", 'RIP'], 8, False, "x86-64")

def get_cachename(cachedir, cachename):
  try:
    os.mkdir(cachedir)
  except:
    pass
  return cachedir + "/" + cachename

def cachewrap(cachedir, cachename, cachegen):
  cachename = get_cachename(cachedir, cachename)
  #import json
  import pickle as json
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
  try:
    cmd = ["which", prog]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    res = p.stdout.readlines()
    if len(res) == 0:
      raise Exception("binary not found")
    return os.path.realpath(res[0].strip())
  except:
    # fallback mode, look for the binary straight up
    if os.path.isfile(prog):
      return os.path.realpath(prog)
    else:
      raise Exception("binary not found")

# things that don't cross the fork
class Program:
  def __init__(self, prog, args):
    # create the logs dir
    try:
      os.mkdir(qira_config.TRACE_FILE_BASE)
    except:
      pass

    # call which to match the behavior of strace and gdb
    self.program = which(prog)
    self.args = args
    self.proghash = sha1(open(self.program, "rb").read()).hexdigest()
    print "*** program is",self.program,"with hash",self.proghash

    # no traces yet
    self.traces = {}
    self.runnable = False

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
    (self.dwarves, self.rdwarves) = ({}, {})
    progdat = open(self.program, "rb").read(0x800)

    if progdat[0:2] == "MZ":
      print "**** windows binary detected, only running the server"
      pe = struct.unpack("I", progdat[0x3c:0x40])[0]
      wh = struct.unpack("H", progdat[pe+4:pe+6])[0]
      if wh == 0x14c:
        print "*** 32-bit windows"
        self.tregs = X86REGS
        self.fb = 0x03
      elif wh == 0x8664:
        print "*** 64-bit windows"
        self.tregs = X64REGS
        self.fb = 0x3e
      else:
        raise Exception("windows binary with machine "+hex(wh)+" not supported")
      return

    # get file type
    self.fb = struct.unpack("H", progdat[0x12:0x14])[0]   # e_machine
    qemu_dir = os.path.dirname(os.path.realpath(__file__))+"/../qemu/"
    pin_dir = os.path.dirname(os.path.realpath(__file__))+"/../pin/"
    self.pinbinary = pin_dir+"pin-latest/pin"

    def use_lib(arch):
      maybe_path = qemu_dir+"/../libs/"+arch+"/"
      if 'QEMU_LD_PREFIX' not in os.environ and os.path.exists(maybe_path):
        os.environ['QEMU_LD_PREFIX'] = os.path.realpath(maybe_path)
        print "**** set QEMU_LD_PREFIX to",os.environ['QEMU_LD_PREFIX']

    if self.fb == 0x28:
      if '/lib/ld-linux.so.3' in progdat:
        use_lib('armel')
      elif '/lib/ld-linux-armhf.so.3' in progdat:
        use_lib('armhf')
      self.tregs = ARMREGS
      self.qirabinary = qemu_dir + "qira-arm"
    elif self.fb == 0xb7:
      use_lib('arm64')
      self.tregs = AARCH64REGS
      self.qirabinary = qemu_dir + "qira-aarch64"
    elif self.fb == 0x3e:
      self.tregs = X64REGS
      self.qirabinary = qemu_dir + "qira-x86_64"
      self.pintool = pin_dir + "obj-intel64/qirapin.so"
    elif self.fb == 0x03:
      self.tregs = X86REGS
      self.qirabinary = qemu_dir + "qira-i386"
      self.pintool = pin_dir + "obj-ia32/qirapin.so"
    elif self.fb == 0x1400:   # big endian...
      use_lib('powerpc')
      self.tregs = PPCREGS
      self.qirabinary = qemu_dir + "qira-ppc"
    else:
      raise Exception("binary type "+hex(self.fb)+" not supported")

    self.qirabinary = os.path.realpath(self.qirabinary)
    print "**** using",self.qirabinary,"for",hex(self.fb)

    self.getdwarf()
    self.runnable = True

  def clear(self):
    # probably always good to do except in development of middleware
    print "*** deleting old runs"
    self.delete_old_runs()

    # getting asm from qemu
    self.create_asm_file()

  def create_asm_file(self):
    if os.name == "nt":
      return
    try:
      os.unlink("/tmp/qira_asm")
    except:
      pass
    open("/tmp/qira_asm", "a").close()
    self.qira_asm_file = open("/tmp/qira_asm", "r")

  def read_asm_file(self):
    if os.name == "nt":
      return
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
    shutil.rmtree(qira_config.TRACE_FILE_BASE)
    os.mkdir(qira_config.TRACE_FILE_BASE)
  
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

    # fix for numberless js
    rret = {}
    for k in ret:
      rret[ghex(k)] = ret[k]
    return rret

  def add_trace(self, fn, i):
    self.traces[i] = Trace(fn, i, self, self.tregs[1], len(self.tregs[0]), self.tregs[2])
    return self.traces[i]

  def execqira(self, args=[], shouldfork=True):
    if self.runnable == False:
      return
    if shouldfork:
      if os.fork() != 0:
        return
    if qira_config.USE_PIN:
      # is "-injection child" good?
      eargs = [self.pinbinary, "-injection", "child", "-t", self.pintool, "--", self.program]+self.args
    else:
      eargs = [self.qirabinary]+self.defaultargs+args+[self.program]+self.args
    #print "***",' '.join(eargs)
    os.execvp(eargs[0], eargs)

  def disasm(self, raw, address):
    try:
      if self.tregs[3] == "i386":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
      elif self.tregs[3] == "x86-64":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
      else:
        raise Exception('arch not in capstone')
      for i in md.disasm(raw, address):
        # should only be one instruction
        return "%s\t%s" % (i.mnemonic, i.op_str)
    except:
      pass
    return raw.encode("hex")

  def research(self, re):
    try:
      csearch = qira.config.CODESEARCHDIR + "/csearch"
      out = subprocess.Popen([csearch, "-n", "--", re], stdout=subprocess.PIPE, env={"CSEARCHINDEX": self.cindexname})
      dat = out.communicate()
      return dat[0].split("\n")[:-1]
    except:
      print "ERROR: csearch not found"
      return []

  def getdwarf(self):
    if not qira_config.WITH_DWARF:
      return

    # DWARF IS STUPIDLY COMPLICATED
    def parse_dwarf():
      files = set()
      dirs = set()
      dwarves = {}
      rdwarves = {}

      from elftools.elf.elffile import ELFFile
      elf = ELFFile(open(self.program))
      if elf.has_dwarf_info():
        fn = None
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
            dirs.add(basedir)
            # get the line program?
            fns = []
            lines = []
            lp = di.line_program_for_CU(cu)
            print "DWARF: CU", basedir, lp['file_entry'][0]
            for f in lp['file_entry']:
              if f == "<built-in>":
                continue
              if f.dir_index > 0 and lp['include_directory'][f.dir_index-1][0] == '/':
                fn = ""
              else:
                fn = basedir
              if f.dir_index > 0:
                fn += lp['include_directory'][f.dir_index-1]+"/"
              # now we have the filename
              fn += f.name
              files.add(fn)
              fns.append(fn)
              lines.append(open(fn).read().split("\n"))
              #print "  DWARF: parsing",fn
              # add all include dirs

            for entry in lp.get_entries():
              s = entry.state
              #print s
              if s != None:
                #print filename, s.line, len(lines)
                dwarves[s.address] = (fns[s.file-1], s.line, lines[s.file-1][s.line-1])
                rd = fns[s.file-1]+"#"+str(s.line)
                if rd not in rdwarves:
                  rdwarves[rd] = s.address
          except Exception as e:
            print "DWARF: error on",fn,"got",e

          # parse in CDA
          if qira_config.WITH_CDA:
            import cachegen
            cfiles = filter(lambda x: x[-2:] != ".h", fns)
            hfiles = filter(lambda x: x[-2:] == ".h", fns)
            ldirs = set()
            for fn in hfiles:
              ep = fn[len(basedir):].split("/")
              for i in range(len(ep)):
                ldirs.add(basedir + "/" + '/'.join(ep[0:i]))
            tmp = []
            for ld in ldirs:
              tmp.append("-I")
              tmp.append(ld)
            #print tmp
            cachegen.parse_files(cfiles, tmp)

      return (list(files), dwarves, rdwarves, list(dirs))

    (files, self.dwarves, self.rdwarves, dirs) = cachewrap("/tmp/qira_dwarfcaches", self.proghash, parse_dwarf)

    self.cindexname = get_cachename("/tmp/qira_cindexcaches", self.proghash)
    if not os.path.isfile(self.cindexname):
      if os.fork() == 0:
        try:
          cindex = qira_config.CODESEARCHDIR + "/cindex"
          os.execve(cindex, [cindex,"--"]+files, {"CSEARCHINDEX": self.cindexname})
        except:
          print "ERROR: cindex not found"
        exit(0)
          
      # no need to wait

    # cda
    if not qira_config.WITH_CDA:
      return

    def parse_cda():
      import cachegen
      return cachegen.parse_files([], [])

    self.cda = cachewrap("/tmp/qira_cdacaches", self.proghash, parse_cda)

class Trace:
  def __init__(self, fn, forknum, program, r1, r2, r3):
    self.forknum = forknum
    self.maxclnum = None
    self.program = program
    self.db = qiradb.Trace(fn, forknum, r1, r2, r3)
    self.load_base_memory()
    self.update_analysis_depends()

  def update_analysis_depends(self):
    if self.maxclnum == None or self.db.get_maxclnum() != self.maxclnum:
      self.minclnum = self.db.get_minclnum()
      self.maxclnum = self.db.get_maxclnum()
      self.flow = qira_analysis.get_instruction_flow(self, self.program, self.minclnum, self.maxclnum)
      self.dmap = qira_analysis.get_hacked_depth_map(self.flow)

  # proxy the db call and fill in base memory
  def fetch_memory(self, clnum, address, ln):
    mem = self.db.fetch_memory(clnum, address, ln)
    dat = {}
    for i in range(ln):
      ri = address+i
      if mem[i] & 0x100:
        dat[ri] = mem[i]&0xFF
      else:
        for (ss, se) in self.base_memory:
          if ss <= ri and ri < se:
            dat[ri] = ord(self.base_memory[(ss,se)][ri-ss])
    return dat

  def load_base_memory(self):
    self.base_memory = {}
    try:
      f = open(qira_config.TRACE_FILE_BASE+str(self.forknum)+"_base")
    except:
      # done
      return

    try:
      from urllib import unquote
      imd = qira_config.TRACE_FILE_BASE+str(self.forknum)+"_images/"
      im = {unquote(i):imd+i for i in os.listdir(imd)}
    except OSError:
      im = {}
    except Exception, e:
      print "Unexpected exception while dealing with _images/:", e
      im = {}

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
        f = open(im.get(fn, fn))
      except:
        continue
      f.seek(offset)
      dat = f.read(se-ss)
      self.base_memory[(ss, se)] = dat
      f.close()

