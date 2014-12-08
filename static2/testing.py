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
from glob import glob

TEST_PATH = os.path.join(qira_config.BASEDIR,"tests_new","binary-autogen","*")
ENGINES = ["builtin"]

class bcolors(object):
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'

ok_green = bcolors.OKGREEN + "[+]" + bcolors.ENDC
warn = bcolors.WARNING + "[-]" + bcolors.ENDC

def get_functions(dwarfinfo):
  function_starts = set()
  for cu in dwarfinfo.iter_CUs():
    for die in cu.iter_DIEs():
      if die.tag == "DW_TAG_subprogram":
        if 'DW_AT_low_pc' in die.attributes:
          function_starts.add(die.attributes['DW_AT_low_pc'].raw_value)
  return function_starts

def test_files(fns,quiet=False,profile=False):
  for fn in fns:
    elf = ELFFile(open(fn))
    if not elf.has_dwarf_info():
      if not quiet:
        print "No dwarf info for {}.".format(fn)
      continue

    dwarfinfo = elf.get_dwarf_info()
    dwarf_functions = get_functions(dwarfinfo)

    engine_functions = {}
    for engine in ENGINES:
      this_engine = Static(fn, debug=True, static_engine=engine)
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

    for engine,functions in engine_functions.iteritems():
      missed = dwarf_functions - functions
      total_fxns = len(dwarf_functions)
      short_fn = fn.split("/")[-1] if "/" in fn else fn
      if len(missed) == 0:
        print "{} {}: {} found all {} function(s).".format(ok_green, short_fn, engine, total_fxns)
      else:
        fmt = "{} {}: {} missed {}/{} functions: {}."
        print fmt.format(warn, short_fn, engine,
                len(missed), total_fxns, ", ".join(hex(fxn) for fxn in missed))

if __name__ == "__main__":
  #todo: radare and summary screen comparing total performance by engine/arch
  parser = argparse.ArgumentParser(description="Test performance of static"
    "engines, requires dwarf test cases.")
  parser.add_argument("files", metavar="file", nargs="*",
                      help="use user-specified binaries")
  parser.add_argument("--quiet",dest="quiet",action="store_true",
                      help="don't warn about missing dwarf information")
  parser.add_argument('--profile',dest="profile",action='store_true',
                      help='use internal profiling, output to prof.png')
  args = parser.parse_args()

  if args.files != []:
    fns = args.files
  else:
    if args.profile:
      print "Profiling over entire test suite. Are you sure that's what you wanted?"
    fns = glob(TEST_PATH)
    if len(fns) == 0:
      print "No files found in {}. Try running python autogen.py --dwarf in the tests directory.".format(TEST_PATH)

  test_files(fns,args.quiet,args.profile)
