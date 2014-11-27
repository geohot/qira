"""
I wanted MIPS support but I couldn't find a GCC with MIPS support in the
standard Ubuntu repos.
"""

SOURCE_DIRECTORY = "source-autogen/"
DEST_DIRECTORY = "binary-autogen/"
ARM_GCC = "arm-linux-gnueabihf-gcc-4.8"
AARCH64_GCC = "aarch64-linux-gnu-gcc-4.8"
PPC_GCC = "powerpc-linux-gnu-gcc-4.8"
PPC64_GCC = "powerpc64le-linux-gnu-gcc-4.8"

import argparse
import os
import subprocess

class arch(object):
  x86     = 0
  x86_64  = 1
  arm     = 2
  aarch64 = 3
  ppc     = 4
  ppc64   = 5

def compiler_command(arch_f,path,filename,strip,dwarf):
  command = []
  raw_filename = ".".join(filename.split(".")[:-1])
  if arch_f == arch.x86:
    command += ["gcc","-m32"]
    raw_filename += "_x86"
  elif arch_f == arch.x86_64:
    command += ["gcc","-m64"]
    raw_filename += "_x86-64"
  elif arch_f == arch.arm:
    command += [ARM_GCC]
    raw_filename += "_arm"
  elif arch_f == arch.aarch64:
    command += [AARCH64_GCC]
    raw_filename += "_aarch64"
  elif arch_f == arch.ppc:
    command += [PPC_GCC]
    raw_filename += "_ppc"
  elif arch_f == arch.ppc64:
    command += [PPC64_GCC]
    raw_filename += "_ppc"
  else:
    print "Invalid archicture"
    return []
  if strip:
    command += ["-s"]
    raw_filename += "_stripped"
  if dwarf:
    command += ["-g"]
    raw_filename += "_dwarf"
  input_fn = os.path.join(path,filename)
  output_fn = os.path.join(DEST_DIRECTORY,raw_filename)
  command += [input_fn,"-o",output_fn]
  return command

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Autogenerate test binaries.")
  parser.add_argument("files", metavar="files", nargs="*",
                      help="use user-specified source files")
  parser.add_argument("--strip",dest="strip",action="store_true",
                      help="strip all generated binaries")
  parser.add_argument("--dwarf",dest="dwarf",action="store_true",
                      help="generate DWARF info with binaries")
  parser.add_argument("--print-only",dest="print_only",action="store_true",
                      help="don't run commands, just print them")
  parser.add_argument("--all",dest="all_arches",action="store_true",
                      help="generate binaries for all supported arches")
  parser.add_argument("--x86",dest="x86",action="store_true",
                      help="generate x86 binaries")
  parser.add_argument("--x64",dest="x64",action="store_true",
                      help="generate x86_64 binaries")
  parser.add_argument("--arm",dest="arm",action="store_true",
                      help="generate arm binaries")
  parser.add_argument("--aarch64",dest="aarch64",action="store_true",
                      help="generate aarch64 binaries")
  parser.add_argument("--ppc",dest="ppc",action="store_true",
                      help="generate ppc binaries")
  parser.add_argument("--ppc64",dest="ppc64",action="store_true",
                      help="generate ppc64 binaries")

  args = parser.parse_args()

  if args.strip and args.dwarf:
    print "Both --strip and --dwarf seleted. Was that intended?"

  arches = []
  if args.all_arches:
    arches = [arch.x86,arch.x86_64,arch.arm,arch.aarch64,arch.ppc,arch.ppc64]
  else:
    if args.x86:
      arches.append(arch.x86)
    if args.x64:
      arches.append(arch.x86_64)
    if args.arm:
      arches.append(arch.arm)
    if args.aarch64:
      arches.append(arch.aarch64)
    if args.ppc:
      arches.append(arch.ppc)
    if args.ppc64:
      arches.append(arch.ppc64)
    if arches == []: #if nothing selected, default to x86 and x86_64
      arches = [arch.x86,arch.x86_64]

  if len(args.files) != 0:
    fns = []
    for fn in args.files:
      if "/" in fn:
        split1 = fn.split("/")
        fn1 = split1[-1]
        path = "/".join(split1[:-1])
        fns.append((path,fn1))
      else:
        fns.append(("./",fn))
  else:
    fns = []
    for path,_,dir_fns in os.walk(SOURCE_DIRECTORY):
      for fn in dir_fns:
        if fn[-2:] == ".c": #in case some non-c files get in the source dir
          fns.append((path,fn))

  #make output directory if it doesn't exist
  if not args.print_only:
    subprocess.call(["mkdir","-p",DEST_DIRECTORY])

  for arch_f in arches:
    for path,fn in fns:
      cmd = compiler_command(arch_f,path,fn,args.strip,args.dwarf)
      if args.print_only:
        print " ".join(cmd)
      else:
        subprocess.call(cmd)
