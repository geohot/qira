"""
I wanted MIPS support but I couldn't find a GCC with MIPS support in the
standard Ubuntu repos.

TODO: think of a good way to deal with programs that need a library import
"""

import argparse
import os
import sys
import subprocess

SOURCE_DIRECTORY = "source-autogen/"
DEST_DIRECTORY = "binary-autogen/"

#If you're not on Ubuntu 14.04, these are up to you.
ARM_GCC = "arm-linux-gnueabihf-gcc-4.8"
AARCH64_GCC = "aarch64-linux-gnu-gcc-4.8"
PPC_GCC = "powerpc-linux-gnu-gcc-4.8"
PPC64_GCC = "powerpc64le-linux-gnu-gcc-4.8"

#http://stackoverflow.com/questions/287871/
#print-in-terminal-with-colors-using-python
class bcolors(object):
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'

class arch(object):
  x86     = 0
  x86_64  = 1
  arm     = 2
  aarch64 = 3
  ppc     = 4
  ppc64   = 5

def compiler_command(path,filename,this_arch,args):
  command = []
  raw_filename = ".".join(filename.split(".")[:-1])

  if args.clang:
    compiler = "clang"
    raw_filename += "_clang"
  else:
    compiler = "gcc"

  if this_arch == arch.x86:
    command += [compiler,"-m32"]
    raw_filename += "_x86"
  elif this_arch == arch.x86_64:
    command += [compiler,"-m64"]
    raw_filename += "_x86-64"
  elif this_arch == arch.arm:
    command += [ARM_GCC]
    raw_filename += "_arm"
  elif this_arch == arch.aarch64:
    command += [AARCH64_GCC]
    raw_filename += "_aarch64"
  elif this_arch == arch.ppc:
    command += [PPC_GCC]
    raw_filename += "_ppc"
  elif this_arch == arch.ppc64:
    command += [PPC64_GCC]
    raw_filename += "_ppc64"
  else:
    print "Invalid archicture"
    return []

  if args.static:
    command += ["-static"]
    raw_filename += "_static"

  if args.strip:
    command += ["-s"]
    raw_filename += "_stripped"

  if args.dwarf:
    command += ["-g"]
    raw_filename += "_dwarf"

  input_fn = os.path.join(path,filename)
  output_fn = os.path.join(DEST_DIRECTORY,raw_filename)
  command += [input_fn,"-o",output_fn]
  return command

def argument_parse():
  parser = argparse.ArgumentParser(description="Autogenerate test binaries.")
  parser.add_argument("files", metavar="file", nargs="*",
                      help="use user-specified source files")
  parser.add_argument("--all",dest="all_archs",action="store_true",
                      help="generate binaries for all supported archs")
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
  parser.add_argument("--static",dest="static",action="store_true",
                      help="static linking")
  parser.add_argument("--strip",dest="strip",action="store_true",
                      help="strip binaries")
  parser.add_argument("--dwarf",dest="dwarf",action="store_true",
                      help="generate DWARF info")
  parser.add_argument("--print-only",dest="print_only",action="store_true",
                      help="don't run commands, just print them")
  parser.add_argument("--clang",dest="clang",action="store_true",
                      help="Use clang instead of gcc (x86, x86-64 only).")
  parser.add_argument("--clean",dest="clean",action="store_true",
                      help="cleanup {}".format(DEST_DIRECTORY))

  return parser.parse_args()

def get_archs(args):
  archs = []
  if args.all_archs:
    archs = [arch.x86,arch.x86_64,arch.arm,arch.aarch64,arch.ppc,arch.ppc64]
  else:
    if args.x86:
      archs.append(arch.x86)
    if args.x64:
      archs.append(arch.x86_64)
    if args.arm:
      archs.append(arch.arm)
    if args.aarch64:
      archs.append(arch.aarch64)
    if args.ppc:
      archs.append(arch.ppc)
    if args.ppc64:
      archs.append(arch.ppc64)
    if archs == []: #if nothing selected, default to x86_64
      archs = [arch.x86_64]
  return archs

def get_files(args):
  fns = []
  if len(args.files) != 0:
    for path in args.files:
      if "/" in path:
        fn = path.split("/")[-1]
        path_real = "/".join(path.split("/")[:-1])
        fns.append((path_real,fn))
      else:
        fns.append(("./",path))
  else:
    for path,_,dir_fns in os.walk(SOURCE_DIRECTORY):
      for fn in dir_fns:
        if fn[-2:] == ".c": #in case some non-c files get in the source dir
          fns.append((path,fn))
  return fns

def process_files(archs,files,args):
  green_plus = bcolors.OKGREEN + "[+]" + bcolors.ENDC
  fail_minus = bcolors.FAIL + "[-]" + bcolors.ENDC

  to_compile = len(archs)*len(files)
  any_failed = False
  progress = 1
  FNULL = open(os.devnull, 'w')

  for this_arch in archs:
    for path,fn in files:
      cmd = compiler_command(path,fn,this_arch,args)
      if args.print_only:
        print " ".join(cmd)
      else:
        print "{} [{}/{}] {}".format(green_plus,
          progress,to_compile," ".join(cmd))
        #don't show warnings
        status = subprocess.call(cmd,stdout=FNULL,stderr=FNULL)
        if status != 0:
          any_failed = True
          fail_path = os.path.join(path,fn)
          print "{} Compilation failed for {}.".format(fail_minus,fail_path)
      progress += 1
  if any_failed:
    print "At least one test failed."
    print "Install ./autogen-extras.sh if necessary."
    print "Otherwise, it's a bug and we're working on it."

if __name__ == "__main__":
  args = argument_parse()

  if args.clean:
    if os.path.exists(DEST_DIRECTORY):
      subprocess.call(["rm","-r",DEST_DIRECTORY])
    sys.exit()

  if args.strip and args.dwarf:
    print "Both --strip and --dwarf seleted. Was that intended?"

  archs = get_archs(args)
  files = get_files(args)

  #make output directory if it doesn't exist
  if not args.print_only:
    subprocess.call(["mkdir","-p",DEST_DIRECTORY])

  process_files(archs,files,args)
