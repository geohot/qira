# *** STATIC TEST STUFF ***

from static2 import *
#import ida
import os
import subprocess
import argparse

import sys

def test_linear(fn):
  linear_static = Static(fn,debug=True)

  function_starts = linear.get_function_starts(linear_static)

  #to cancel out recursive's default advantage
  function_starts.add(linear_static.get_address_by_name("main"))
  function_starts.add(linear_static['entry'])

  recursive.make_functions_from_starts(linear_static,function_starts)

  return linear_static


def test_recursive(fn):
  recursive_static = Static(fn,debug=True)

  # find main
  main = recursive_static.get_address_by_name("main")
  #print "main is at", hex(main)
  recursive.make_function_at(recursive_static, recursive_static['entry'], recurse=True)
  #print "recursive descent found %d functions" % len(recursive_static['functions'])
  recursive.make_function_at(recursive_static, main, recurse=True)
  #print "recursive descent found %d functions" % len(recursive_static['functions'])

  return recursive_static

def function_printer(static):
  for f in sorted(static['functions']):
    print static[f.start]['name'] or hex(f.start), f
    for b in sorted(f.blocks):
      print "  ",b
      for a in sorted(b.addresses):
        print "    ",hex(a),static._insert_names(static[a]['instruction'])

def test_byteweight(static):
  bw_functions = byteweight.fsi(recursive_static)
  for f in bw_functions:
    print hex(f)
    hexdump(recursive_static.memory(f, 0x20))

def test(fns):
  #nonstrippednonida = [x for x in nonstripped if not os.path.isfile(x+".ida_info")]
  #print "Please generate an ida_info file for the following:",nonstrippednonida
  #sys.exit()

  d = {}
  d['i386_total_fns'] = 0
  d['i386_missed_lin'] = 0
  d['i386_missed_rec'] = 0
  d['x86-64_total_fns'] = 0
  d['x86-64_missed_lin'] = 0
  d['x86-64_missed_rec'] = 0
  d['arm_total_fns'] = 0
  d['arm_missed_lin'] = 0
  d['arm_missed_rec'] = 0
  d['aarch64_total_fns'] = 0
  d['aarch64_missed_lin'] = 0
  d['aarch64_missed_rec'] = 0

  #each argument is a set of addresses and names (we take the intersection by address)
  #functions1-functions2
  def get_missed(functions1,functions2):
    f1_addresses = set(x[0] for x in functions1)
    f2_addresses = set(x[0] for x in functions2)
    return f1_addresses-f2_addresses
    #return set(x[1] for x in functions1 if x[0] in (f1_addresses-f2_addresses))

  def static_to_function_set(static):
    return set((f.start,static[f.start]['name']) for f in static['functions'])

  #for fn in nonstripped:
  ##  recursive_static = test_recursive(fn)
  #  print fn,len(recursive_static['debug_functions'])
  #sys.exit()

  num_nonstripped = len(nonstripped)

  for i,fn in enumerate(nonstripped):
    print "[{}/{}] {}".format(i+1,num_nonstripped,fn)
    linear_static = test_linear(fn)
    recursive_static = test_recursive(fn)
    arch = linear_static['arch']
    ida_available = False #disable IDA for now
    #ida_available = arch in ['i386','x86-64']
    #if not ida_available:
    #  print "ida not enabled"

    #test_byteweight(Static(fn,debug=True))

    real_functions = linear_static['debug_functions']
    linear_functions = static_to_function_set(linear_static)
    recursive_functions = static_to_function_set(recursive_static)
    if ida_available:
      ida.init_with_binary(fn)
      ida_tags = ida.fetch_tags()
      ida_functions = set((f,recursive_static[f]['name']) for f in ida_tags.keys()) #keys for tags from IDA are the function addresses?

    num_real_functions = len(real_functions)

    if arch == "i386":
      d['i386_total_fns'] += num_real_functions
      d['i386_missed_lin'] += len(get_missed(real_functions,linear_functions))
      d['i386_missed_rec'] += len(get_missed(real_functions,recursive_functions))
    elif arch == "x86-64":
      d['x86-64_total_fns'] += num_real_functions
      d['x86-64_missed_lin'] += len(get_missed(real_functions,linear_functions))
      d['x86-64_missed_rec'] += len(get_missed(real_functions,recursive_functions))
    elif arch == "arm":
      d['arm_total_fns'] += num_real_functions
      d['arm_missed_lin'] += len(get_missed(real_functions,linear_functions))
      d['arm_missed_rec'] += len(get_missed(real_functions,recursive_functions))
    elif arch == "aarch64":
      d['aarch64_total_fns'] += num_real_functions
      d['aarch64_missed_lin'] += len(get_missed(real_functions,linear_functions))
      d['aarch64_missed_rec'] += len(get_missed(real_functions,recursive_functions))
    else:
      print "unknown arch",arch

  if d['i386_total_fns'] != 0:
    print "\ni386:"
    print "Total functions (from symbols):       {}".format(d['i386_total_fns'])
    print "Functions found by linear sweep:      {}".format(d['i386_total_fns']-d['i386_missed_lin'])
    print "Functions found by recursive descent: {}".format(d['i386_total_fns']-d['i386_missed_rec'])

  if d['x86-64_total_fns'] != 0:
    print "\nx86-64:"
    print "Total functions (from symbols):       {}".format(d['x86-64_total_fns'])
    print "Functions found by linear sweep:      {}".format(d['x86-64_total_fns']-d['x86-64_missed_lin'])
    print "Functions found by recursive descent: {}".format(d['x86-64_total_fns']-d['x86-64_missed_rec'])

  if d['arm_total_fns'] != 0:
    print "\nARM:"
    print "Total functions (from symbols):       {}".format(d['arm_total_fns'])
    print "Functions found by linear sweep:      {}".format(d['arm_total_fns']-d['arm_missed_lin'])
    print "Functions found by recursive descent: {}".format(d['arm_total_fns']-d['arm_missed_rec'])

  if d['aarch64_total_fns'] != 0:
    print "\nAARCH64:"
    print "Total functions (from symbols):       {}".format(d['aarch64_total_fns'])
    print "Functions found by linear sweep:      {}".format(d['aarch64_total_fns']-d['aarch64_missed_lin'])
    print "Functions found by recursive descent: {}".format(d['aarch64_total_fns']-d['aarch64_missed_rec'])

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('--file', help="a single file to test (must have symbols)")
  #parser.add_argument('--profile', dest='profile_enabled', action='store_true')
  args = parser.parse_args()

  #if args.profile_enabled:
  #  import cProfile
  #  cProfile.run("test()")

  if args.file is None:
    fns = [os.path.join(path,fn) for path,_,fns in os.walk("../tests/") for fn in fns]
  else:
    fns = [args.file]

  #get nonstripped elf binaries (this is hacky)
  nonstripped = []
  for fn in fns:
    info = subprocess.check_output(["file",fn])
    if "ELF" in info and "not stripped" in info:
      nonstripped.append(fn)

  test(nonstripped)
