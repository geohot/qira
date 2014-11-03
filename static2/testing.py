# *** STATIC TEST STUFF ***

from static2 import *
#import ida
import os
import subprocess

import sys

def test_linear(fn):
  linear_static = Static(fn,debug=True)
  print "arch:",linear_static['arch']

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

if __name__ == "__main__":
  #if len(sys.argv) != 2:
  #  print "Please provide a binary to test as an argument."
  #  sys.exit(1)

  #get all files in ../tests/
  fns = [os.path.join(path,fn) for path,_,fns in os.walk("../tests/") for fn in fns]

  #get nonstripped elf binaries (this is hacky)
  nonstripped = []
  for fn in fns:
    info = subprocess.check_output(["file",fn])
    if "ELF" in info and "not stripped" in info:
      nonstripped.append(fn)

  d = {}
  d['total_fns'] = 0
  d['missed_lin'] = 0
  d['missed_rec'] = 0

  #each argument is a set of addresses and names (we take the intersection by address)
  #functions1-functions2
  def get_missed(functions1,functions2):
    f1_addresses = set(x[0] for x in functions1)
    f2_addresses = set(x[0] for x in functions2)
    return f1_addresses-f2_addresses
    #return set(x[1] for x in functions1 if x[0] in (f1_addresses-f2_addresses))

  def static_to_function_set(static):
    return set((f.start,static[f.start]['name']) for f in static['functions'])

  for fn in nonstripped:
    print "testing",fn
    linear_static = test_linear(fn)
    recursive_static = test_recursive(fn)
    arch = linear_static['arch']
    ida_available = False #disable IDA for now
    #ida_available = arch in ['i386','x86-64']
    if not ida_available:
      print "ida not enabled"

    #test_byteweight(Static(fn,debug=True))

    real_functions = linear_static['debug_functions']
    linear_functions = static_to_function_set(linear_static)
    recursive_functions = static_to_function_set(recursive_static)
    if ida_available:
      ida.init_with_binary(fn)
      ida_tags = ida.fetch_tags()
      ida_functions = set((f,recursive_static[f]['name']) for f in ida_tags.keys()) #keys for tags from IDA are the function addresses?

    num_real_functions = len(real_functions)

    d['total_fns'] += num_real_functions
    d['missed_lin'] = len(get_missed(real_functions,linear_functions))
    d['missed_rec'] = len(get_missed(real_functions,recursive_functions))

  print "Total functions across binaries:",d['total_fns']
  print "Functions missed by linear sweep:",d['missed_lin']
  print "Funtions missed by recursive descent:",d['missed_rec']
