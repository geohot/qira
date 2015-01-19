#!/usr/bin/env python2.7

#needed for qira_config
import sys
import os
sys.path.insert(0, os.path.join('..','middleware'))
import qira_config

from static2 import *
import subprocess
import argparse

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from glob import glob

TEST_PATH = os.path.join(qira_config.BASEDIR,"tests_source","binary-autogen","*")
ENGINES = ["builtin"]

class bcolors(object):
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'

ok_green = bcolors.OKGREEN + "[+]" + bcolors.ENDC
ok_blue  = bcolors.OKBLUE  + "[+]" + bcolors.ENDC
warn     = bcolors.WARNING + "[-]" + bcolors.ENDC
fail     = bcolors.FAIL    + "[!]" + bcolors.ENDC

def get_functions(dwarfinfo):
  function_starts = set()
  for cu in dwarfinfo.iter_CUs():
    try:
      for die in cu.iter_DIEs():
        if die.tag == "DW_TAG_subprogram":
          if 'DW_AT_low_pc' in die.attributes:
            function_starts.add(die.attributes['DW_AT_low_pc'].raw_value)
    except:
      continue
  return function_starts

def test_files(fns,quiet=False,profile=False):
  for fn in fns:
    short_fn = fn.split("/")[-1] if "/" in fn else fn
    if os.path.isdir(fn):
      if not quiet:
        print "{} {}: skipping directory".format(warn, short_fn)
      continue
    try:
      elf = ELFFile(open(fn))
    except ELFError:
      if not quiet:
        print "{} {}: skipping non-ELF file".format(warn, short_fn)
      continue

    engine_functions = {}
    for engine in ENGINES:
      try:
        this_engine = Static(fn, debug=0, static_engine=engine) #no debug output
        if args.profile:
          #needs pycallgraph
          from pycallgraph import PyCallGraph
          from pycallgraph.output import GraphvizOutput
          graphviz = GraphvizOutput()
          graphviz.output_file = 'prof.png'
          with PyCallGraph(output=graphviz):
            this_engine.process()
        else:
          this_engine.process()
        engine_functions[engine] = {x.start for x in this_engine['functions']}
      except:
        print "{} {}: {} engine failed to process file".format(fail, short_fn, engine)
        continue

    if elf.has_dwarf_info():
      dwarfinfo = elf.get_dwarf_info()
      dwarf_functions = get_functions(dwarfinfo)
      for engine,functions in engine_functions.iteritems():
        missed = dwarf_functions - functions
        total_fxns = len(dwarf_functions)
        if len(missed) == 0:
          print "{} {}: {} engine found all {} function(s)".format(ok_green, short_fn, engine, total_fxns)
        else:
          status = fail if len(missed) == total_fxns else warn
          if args.verbose:
            fmt = "{} {}: {} engine missed {}/{} function(s): {}"
            missed_s = ", ".join(hex(fxn) for fxn in missed)
            print fmt.format(status, short_fn, engine,
                    len(missed), total_fxns, missed_s)
          else:
            fmt = "{} {}: {} engine missed {}/{} function(s)"
            print fmt.format(status, short_fn, engine,
                    len(missed), total_fxns)
    else:
      for engine,functions in engine_functions.iteritems():
        status = fail if len(functions) == 0 else ok_blue
        print "{} {}: {} engine found {} function(s). (dwarf info unavailable)".format(status, short_fn, engine, len(functions))

def get_file_list(location, recursive=False):
  if not recursive:
    fns = []
    for loc in location:
      for fn in glob(loc):
        if not os.path.isdir(fn):
          fns.append(fn)
    return fns
  fns = []
  for loc in location:
    for fn in glob(loc):
      if os.path.isdir(fn):
        for root, dirnames, filenames in os.walk(fn):
          fns += [os.path.join(root, f) for f in filenames]
      else:
        fns.append(fn)
  return fns

if __name__ == "__main__":
  #todo: radare and summary screen comparing total performance by engine/arch
  parser = argparse.ArgumentParser(description="Test performance of static"
    "engines, takes advantage of DWARF information if present.")
  parser.add_argument("files", metavar="file", nargs="*",
                      help="use user-specified binaries")
  parser.add_argument("--recursive","-r",dest="recursive",action="store_true",
                      help="recurse into directories when checking")
  parser.add_argument("--quiet",dest="quiet",action="store_true",
                      help="don't warn about skipped cases")
  parser.add_argument('--profile',dest="profile",action='store_true',
                      help='use internal profiling, output to prof.png')
  parser.add_argument('--verbose',dest="verbose",action="store_true",
                      help='show all missed functions')
  args = parser.parse_args()

  if args.files != []:
    fns = get_file_list(args.files, args.recursive)
  else:
    if args.profile:
      print "Profiling over entire test suite. Are you sure that's what you wanted?"
    fns = get_file_list([TEST_PATH], args.recursive)
    if len(fns) == 0:
      print "No files found in {}. Try running python autogen.py --dwarf in the tests directory.".format(TEST_PATH)

  test_files(fns,args.quiet, args.profile)
