from __future__ import print_function
from qira_base import *
import qira_config
import qira_analysis

import os
import shutil
import sys
import subprocess
import threading
import time
import collections
from hashlib import sha1

from subprocess import (Popen, PIPE)
import json

import struct
import qiradb

import arch

# new home of static2
sys.path.append(qira_config.BASEDIR+"/static2")
import static2
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
  def __init__(self, prog, args=[], qemu_args=[]):
    # create the logs dir
    try:
      os.mkdir(qira_config.TRACE_FILE_BASE)
    except:
      pass

    # call which to match the behavior of strace and gdb
    self.program = which(prog)
    self.args = args
    self.proghash = sha1(open(self.program, "rb").read()).hexdigest()
    print("*** program is",self.program,"with hash",self.proghash)

    # this is always initted, as it's the tag repo
    self.static = static2.Static(self.program)

    # init static
    if qira_config.WITH_STATIC:
      threading.Thread(target=self.static.process).start()

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
    self.defaultargs = ["-strace", "-D", "/dev/null", "-d", "in_asm", "-singlestep"]+qemu_args
    if qira_config.TRACE_LIBRARIES:
      self.defaultargs.append("-tracelibraries")

    self.identify_program()

  def identify_program(self):
    qemu_dir = os.path.dirname(os.path.realpath(__file__))+"/../tracers/qemu/"
    pin_dir = os.path.dirname(os.path.realpath(__file__))+"/../tracers/pin/"
    lib_dir = os.path.dirname(os.path.realpath(__file__))+"/../libs/"
    self.pinbinary = pin_dir+"pin-latest/pin"

    # pmaps is global, but updated by the traces
    progdat = open(self.program, "rb").read(0x800)

    CPU_TYPE_ARM = b"\x0C"
    CPU_TYPE_ARM64 = b"\x01\x00\x00\x0C"

    CPU_SUBTYPE_ARM_ALL = b"\x00"
    CPU_SUBTYPE_ARM_V4T = b"\x05"
    CPU_SUBTYPE_ARM_V6 = b"\x06"
    CPU_SUBTYPE_ARM_V5TEJ = b"\x07"
    CPU_SUBTYPE_ARM_XSCALE = b"\x08"
    CPU_SUBTYPE_ARM_V7 = b"\x09"
    CPU_SUBTYPE_ARM_V7F = b"\x0A"
    CPU_SUBTYPE_ARM_V7S = b"\x0B"
    CPU_SUBTYPE_ARM_V7K = b"\x0C"
    CPU_SUBTYPE_ARM_V6M = b"\x0E"
    CPU_SUBTYPE_ARM_V7M = b"\x0F"
    CPU_SUBTYPE_ARM_V7EM = b"\x10"

    CPU_SUBTYPE_ARM = [
                         CPU_SUBTYPE_ARM_V4T,
                         CPU_SUBTYPE_ARM_V6,
                         CPU_SUBTYPE_ARM_V5TEJ,
                         CPU_SUBTYPE_ARM_XSCALE,
                         CPU_SUBTYPE_ARM_V7,
                         CPU_SUBTYPE_ARM_V7F,
                         CPU_SUBTYPE_ARM_V7K,
                         CPU_SUBTYPE_ARM_V6M,
                         CPU_SUBTYPE_ARM_V7M,
                         CPU_SUBTYPE_ARM_V7EM
                      ]

    CPU_SUBTYPE_ARM64 = [
                         CPU_SUBTYPE_ARM_ALL,
                         CPU_SUBTYPE_ARM_V7S
                        ]

    MACHO_MAGIC = b"\xFE\xED\xFA\xCE"
    MACHO_CIGAM = b"\xCE\xFA\xED\xFE"
    MACHO_MAGIC_64 = b"\xFE\xED\xFA\xCF"
    MACHO_CIGAM_64 = b"\xCF\xFA\xED\xFE"
    MACHO_FAT_MAGIC = b"\xCA\xFE\xBA\xBE"
    MACHO_FAT_CIGAM = b"\xBE\xBA\xFE\xCA"
    MACHO_P200_FAT_MAGIC = b"\xCA\xFE\xD0\x0D"
    MACHO_P200_FAT_CIGAM = b"\x0D\xD0\xFE\xCA"

    # Linux binaries
    if progdat[0:4] == b"\x7FELF":
      # get file type
      self.fb = struct.unpack("H", progdat[0x12:0x14])[0]   # e_machine

      def use_lib(arch):
        maybe_path = lib_dir+arch+"/"
        if 'QEMU_LD_PREFIX' not in os.environ and os.path.exists(maybe_path):
          os.environ['QEMU_LD_PREFIX'] = os.path.realpath(maybe_path)
          print("**** set QEMU_LD_PREFIX to",os.environ['QEMU_LD_PREFIX'])

      if self.fb == 0x28:
        if '/lib/ld-linux.so.3' in progdat:
          use_lib('armel')
        elif '/lib/ld-linux-armhf.so.3' in progdat:
          use_lib('armhf')
        self.tregs = arch.ARMREGS
        self.qirabinary = qemu_dir + "qira-arm"
      elif self.fb == 0xb7:
        use_lib('arm64')
        self.tregs = arch.AARCH64REGS
        self.qirabinary = qemu_dir + "qira-aarch64"
      elif self.fb == 0x3e:
        self.tregs = arch.X64REGS
        self.qirabinary = qemu_dir + "qira-x86_64"
        self.pintool = pin_dir + "obj-intel64/qirapin.so"
      elif self.fb == 0x03:
        use_lib('i386')
        self.tregs = arch.X86REGS
        self.qirabinary = qemu_dir + "qira-i386"
        self.pintool = pin_dir + "obj-ia32/qirapin.so"
      elif self.fb == 0x800:
        use_lib('mips')
        arch.MIPSREGS[2:-1] = (True, "mips")
        self.tregs = arch.MIPSREGS
        self.qirabinary = qemu_dir + 'qira-mips'
      elif self.fb == 0x08:
        use_lib('mipsel')
        arch.MIPSREGS[2:-1] = (False, "mipsel")
        self.tregs = arch.MIPSREGS
        self.qirabinary = qemu_dir + 'qira-mipsel'
      elif self.fb == 0x1400:   # big endian...
        use_lib('powerpc')
        self.tregs = arch.PPCREGS
        self.qirabinary = qemu_dir + "qira-ppc"
      else:
        raise Exception("binary type "+hex(self.fb)+" not supported")

      self.qirabinary = os.path.realpath(self.qirabinary)
      print("**** using",self.qirabinary,"for",hex(self.fb))

      self.runnable = True

    # Windows binaries
    elif progdat[0:2] == b"MZ":
      print("**** windows binary detected, only running the server")
      pe = struct.unpack("I", progdat[0x3c:0x40])[0]
      wh = struct.unpack("H", progdat[pe+4:pe+6])[0]
      if wh == 0x14c:
        print("*** 32-bit windows")
        self.tregs = arch.X86REGS
        self.fb = 0x03
      elif wh == 0x8664:
        print("*** 64-bit windows")
        self.tregs = arch.X64REGS
        self.fb = 0x3e
      else:
        raise Exception("windows binary with machine "+hex(wh)+" not supported")

    # MACHO FAT binaries
    elif progdat[0x0:0x04] in (MACHO_FAT_MAGIC, MACHO_FAT_CIGAM, MACHO_P200_FAT_MAGIC, MACHO_P200_FAT_CIGAM):
      print("**** Mach-O FAT (Universal) binary detected")

      if progdat[0x04:0x05] == CPU_TYPE_ARM and progdat[0x08:0x09] in CPU_SUBTYPE_ARM:
        print("**** Mach-O ARM architecture detected")
        self.macharch = "arm"
      elif (progdat[0x08:0x0c] == CPU_TYPE_ARM64) or (progdat[0x1c:0x20] == CPU_TYPE_ARM64) or (progdat[0x30:0x34] == CPU_TYPE_ARM64):
        print("**** Mach-O Aarch64 architecture detected")
        self.macharch = "aarch64"
      else:
        self.macharch = ""
        print("**** Mach-O X86/64 architecture detected")

      if progdat[0x0:0x04] in (MACHO_P200_FAT_MAGIC, MACHO_P200_FAT_CIGAM):
        raise NotImplementedError("Pack200 compressed files are not supported yet")
      elif progdat[0x0:0x04] in (MACHO_FAT_MAGIC, MACHO_FAT_CIGAM):
        if progdat[0x0:0x04] == MACHO_FAT_CIGAM:
          arch.ARMREGS[2] = True
          arch.AARCH64REGS[2] = True
        if self.macharch == "arm":
          self.tregs = arch.ARMREGS
          self.pintool = ""
        elif self.macharch == "aarch64":
          self.tregs = arch.AARCH64REGS
          self.pintool = ""
        else:
          self.tregs = arch.X86REGS
          self.pintool = pin_dir + "obj-ia32/qirapin.dylib"
      else:
        raise Exception("Mach-O FAT (Universal) binary not supported")
      if self.macharch == "arm" or self.macharch == "aarch64":
        raise NotImplementedError("ARM/Aarch64 Support is not implemented")
      if not os.path.isfile(self.pintool):
        print("Running a Mach-O FAT (Universal) binary requires PIN support. See tracers/pin_build.sh")
        exit()
      raise NotImplementedError("Mach-O FAT (Universal) binary not supported")
      self.runnable = True

    # MACHO binaries
    elif progdat[0x0:0x04] in (MACHO_MAGIC_64, MACHO_CIGAM_64, MACHO_MAGIC, MACHO_CIGAM):
      print("**** Mach-O binary detected")

      if progdat[0x04:0x05] == CPU_TYPE_ARM and progdat[0x08:0x09] in CPU_SUBTYPE_ARM:
        print("**** Mach-O ARM architecture detected")
        self.macharch = "arm"
      elif progdat[0x04:0x05] == CPU_TYPE_ARM and progdat[0x08:0x09] in CPU_SUBTYPE_ARM64:
        print("**** Mach-O Aarch64 architecture detected")
        self.macharch = "aarch64"
      else:
        self.macharch = ""
        print("**** Mach-O X86/64 architecture detected")

      if progdat[0x0:0x04] in (MACHO_MAGIC_64, MACHO_CIGAM_64):
        if progdat[0x0:0x04] == MACHO_CIGAM_64:
          arch.AARCH64REGS[2] = True
        if self.macharch == "aarch64":
          self.tregs = arch.AARCH64REGS
          self.pintool = ""
        else:
          self.tregs = arch.X64REGS
          self.pintool = pin_dir + "obj-intel64/qirapin.dylib"
      elif progdat[0x0:0x04] in (MACHO_MAGIC, MACHO_CIGAM):
        if progdat[0x0:0x04] == MACHO_CIGAM:
          arch.ARMREGS[2] = True
        if self.macharch == "arm":
          self.tregs = arch.ARMREGS
          self.pintool = ""
        else:
          self.tregs = arch.X86REGS
          self.pintool = pin_dir + "obj-ia32/qirapin.dylib"
      else:
        raise Exception("Mach-O binary not supported")
      if self.macharch == "arm" or self.macharch == "aarch64":
        raise NotImplementedError("ARM/Aarch64 Support is not implemented")
      if not os.path.isfile(self.pintool):
        print("Running a Mach-O binary requires PIN support. See tracers/pin_build.sh")
        exit()
      self.runnable = True
    else:
      raise Exception("unknown binary type")

  def clear(self, delete_old_runs=True):
    # probably always good to do except in development of middleware
    if delete_old_runs:
      print("*** deleting old runs")
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
      thumb = False
      if len(d) == 0:
        continue
      # hacks
      try:
        if self.fb == 0x28:
          #thumb bit in front
          addr = int(d.split(" ")[0][1:].strip(":"), 16)
        else:
          addr = int(d.split(" ")[0].strip(":"), 16)
      except:
        continue
      if self.fb == 0x28:
        thumb_flag = d[0]
        if thumb_flag == 't':
          thumb = True
          # override the arch since it's thumb, clear invalid tag
          del self.static[addr]['instruction']
          self.static[addr]['arch'] = "thumb"
        elif thumb_flag == 'n':
          thumb = False
        else:
          #print "*** Invalid thumb flag at beginning of instruction"
          pass
        inst = d[d.rfind("  ")+2:]
      elif self.fb == 0xb7:   # aarch64
        inst = d[d.rfind("     ")+5:]
      else:
        inst = d[d.find(":")+3:]
      cnt += 1

      # trigger disasm
      d = self.static[addr]['instruction']

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
    if qira_config.USE_PIN:
      # is "-injection child" good?
      eargs = [self.pinbinary, "-injection", "child", "-t", self.pintool, "--", self.program]+self.args
    else:
      eargs = [self.qirabinary]+self.defaultargs+args+[self.program]+self.args
    if not os.path.exists(eargs[0]):
      print("\nQIRA tracer %s not found" % eargs[0])
      print("Your install is broken. Check ./install.sh for issues")
      exit(-1)
    if shouldfork:
      if os.fork() != 0:
        return
    #print "***",' '.join(eargs)
    os.execvp(eargs[0], eargs)


class Trace:
  def __init__(self, fn, forknum, program, r1, r2, r3):
    self.forknum = forknum
    self.program = program
    self.db = qiradb.PyTrace(fn, forknum, r1, r2, r3)
    self.load_base_memory()

    # analysis stuff
    self.maxclnum = None
    self.minclnum = None
    self.flow = None
    self.dmap = None
    self.maxd = 0
    self.analysisready = False
    self.picture = None
    self.needs_update = False
    self.strace = []
    self.mapped = []

    self.keep_analysis_thread = True
    threading.Thread(target=self.analysis_thread).start()

  def fetch_raw_memory(self, clnum, address, ln):
    return ''.join(map(chr, self.fetch_memory(clnum, address, ln).values()))

  # proxy the db call and fill in base memory
  def fetch_memory(self, clnum, address, ln):
    mem = self.db.fetch_memory(clnum, address, ln)
    dat = {}
    for i in range(ln):
      # we don't rebase the memory anymore, important for numberless
      ri = address+i
      if mem[i] & 0x100:
        dat[i] = mem[i]&0xFF
      else:
        try:
          if (sys.version_info > (3, 0)):
            dat[i] = self.program.static.memory(ri, 1)[0]
          else:
            dat[i] = ord(self.program.static.memory(ri, 1)[0])
        except IndexError:
          pass
    return dat

  def read_strace_file(self):
    try:
      f = open(qira_config.TRACE_FILE_BASE+str(int(self.forknum))+"_strace").read()
    except:
      return "no strace"

    f = ''.join(filter(lambda x: ord(x) < 0x80, f))
    ret = []
    files = {}
    for ff in f.split("\n"):
      if ff == '':
        continue
      ff = ff.split(" ")
      try:
        clnum = int(ff[0])
      except:
        continue
      # i think this filter isn't so useful now
      pid = int(ff[1])
      sc = " ".join(ff[2:])
      try:
        return_code = int(sc.split(") = ")[1].split(" ")[0], 0)
        fxn = sc.split("(")[0]
        if (fxn == "open" or fxn == "openat") and return_code != -1:
          firststr = sc.split('\"')[1]
          files[return_code] = firststr
        elif fxn[0:4] == "mmap":
          args = sc.split(",")
          sz = int(args[1], 0)
          fil = int(args[4], 0)
          off = int(args[5].split(")")[0], 0)
          mapp = (files[fil], sz, off, return_code)
          if mapp not in self.mapped:
            # if it fails once, don't try again
            self.mapped.append(mapp)
            try:
              try:
                f = open(os.environ['QEMU_LD_PREFIX']+"/"+files[fil], 'rb')
              except:
                f = open(files[fil], 'rb')
              alldat = f.read()

              if fxn == "mmap2":
                off = 4096*off # offset argument is in terms of pages for mmap2()
                # is it safe to assume 4096 byte pages?

              st = "*** mapping %s %s sz:0x%x off:0x%x @ 0x%X" % (sha1(alldat).hexdigest(), files[fil], sz, off, return_code)
              print(st,)
              dat = alldat[off:off+sz]

              self.program.static.add_memory_chunk(return_code, dat)
            except Exception as e:
              print(e)

      except:
        pass
      ret.append({"clnum": clnum, "pid":pid, "sc": sc})

    self.strace = ret

  def analysis_thread(self):
    print("*** started analysis_thread", self.forknum)
    while self.keep_analysis_thread:
      time.sleep(0.2)
      # so this is done poorly, analysis can be incremental
      if self.maxclnum == None or self.db.get_maxclnum() != self.maxclnum:
        self.analysisready = False
        minclnum = self.db.get_minclnum()
        maxclnum = self.db.get_maxclnum()
        self.program.read_asm_file()
        self.flow = qira_analysis.get_instruction_flow(self, self.program, minclnum, maxclnum)
        self.dmap = qira_analysis.get_hacked_depth_map(self.flow, self.program)
        qira_analysis.analyse_calls(self)

        # hacky pin offset problem fix
        hpo = len(self.dmap)-(maxclnum-minclnum)
        if hpo == 2:
          self.dmap = self.dmap[1:]

        self.maxd = max(self.dmap)
        self.picture = qira_analysis.get_vtimeline_picture(self, minclnum, maxclnum)
        self.minclnum = minclnum
        self.maxclnum = maxclnum
        self.needs_update = True

        #print "analysis is ready"
    print("*** ended analysis_thread", self.forknum)

  def load_base_memory(self):
    def get_forkbase_from_log(n):
      ret = struct.unpack("i", open(qira_config.TRACE_FILE_BASE+str(n), 'rb').read(0x18)[0x10:0x14])[0]
      if ret == -1:
        return n
      else:
        return get_forkbase_from_log(ret)

    try:
      forkbase = get_forkbase_from_log(self.forknum)
      print("*** using base %d for %d" % (forkbase, self.forknum))
      f = open(qira_config.TRACE_FILE_BASE+str(forkbase)+"_base", 'r')
    except Exception as e:
      print("*** base file issue",e)
      # done
      return

    # Use any bundled images first. The structure of the images directory is:
    # _images/
    #   urlencoded%20image.dll
    #   or%20maybe%20a%20folder.dll/
    #     0000C000
    #     100008000
    # where a folder is like a sparsefile with chunks of data at it's hex-offset-named
    # subfiles. The reason for this sparsefile stuff is that OS X has non-contigous
    # loaded images, so we compensate by having each "file" actually be a chunk of
    # address space, which in theory could be very large. (The correct solution of
    # storing just the image file along with the regions data isn't well exposed
    # by Pin at this time, and would require explicit mach-o parsing and stuff.)
    img_map = {}
    images_dir = qira_config.TRACE_FILE_BASE+str(self.forknum)+"_images"
    if os.path.isdir(images_dir):
      try:
        from urllib import unquote
        for image in os.listdir(images_dir):
          if os.path.isfile(images_dir+"/"+image):
            img_map[unquote(image)] = {0: images_dir+"/"+image}
          else: # It's a directory
            off_map = {}
            for offset in os.listdir(images_dir+"/"+image):
              off_map[int(offset, 16)] = images_dir+"/"+image+"/"+offset
            img_map[unquote(image)] = off_map
      except Exception as e:
        print("Exception while dealing with _images/:", e)

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
        if fn in img_map:
          off = max(i for i in img_map[fn].iter_keys() if i <= offset)
          with open(img_map[fn][off], 'rb') as f:
            f.seek(offset-off)
            dat = f.read(se-ss)
        else:
          with open(fn, 'rb') as f:
            f.seek(offset)
            dat = f.read(se-ss)
      except Exception as e:
        print("Failed to get", fn, "offset", offset, ":", e)
        continue
      self.program.static.add_memory_chunk(ss, dat)
