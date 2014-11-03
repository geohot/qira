# *** STATIC TEST STUFF ***

from static2 import *
import ida #ida.py from this file, needs ida demo in appropriate directory

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
  recursive_static = Static(sys.argv[1],debug=True)

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
  if len(sys.argv) != 2:
    print "Please provide a binary to test as an argument."
    sys.exit(1)
  fn = sys.argv[1]
  linear_static = test_linear(fn)
  recursive_static = test_recursive(fn)

  #test_byteweight(Static(fn,debug=True))

  real_functions = linear_static['debug_functions']
  linear_functions = set((f.start,linear_static[f.start]['name']) for f in linear_static['functions'])
  recursive_functions = set((f.start,recursive_static[f.start]['name']) for f in recursive_static['functions'])
  ida.init_with_binary(fn)
  ida_tags = ida.fetch_tags()
  print "*** ida returned %d tags" % (len(tags))
  ida_functions = set((f,recursive_static[f.start]['name']) for f in ida_tags.keys()) #keys for tags from IDA are the function addresses?
  print ida_functions

  """
  real_functions, linear_functions, and recursive_functions all are sets of
  tuples (address, name) for each function identified
  """

  real_addresses = set(x[0] for x in real_functions)
  linear_addresses = set(x[0] for x in linear_functions)
  recursive_addresses = set(x[0] for x in recursive_functions)

  print "ELF symbols:       {} functions found.".format(len(real_addresses))
  print "Linear sweep:      {} functions found.".format(len(linear_addresses))
  print "Recursive descent: {} functions found.".format(len(recursive_addresses))

  linear_missed = set(x[1] for x in real_functions if x[0] in (real_addresses-linear_addresses))
  recursive_missed = set(x[1] for x in real_functions if x[0] in (real_addresses-recursive_addresses))
  linear_not_rec = set(x[1] for x in linear_functions if x[0] in (linear_addresses-recursive_addresses))
  rec_not_linear = set(x[1] for x in recursive_functions if x[0] in recursive_addresses-linear_addresses)

  linear_false_pos = set(x[1] for x in linear_functions if x[0] in (linear_addresses-real_addresses))
  recursive_false_pos = set(x[1] for x in linear_functions if x[0] in (recursive_addresses-real_addresses))

  #print "Functions missed by linear sweep:",linear_missed,"\n"
  #print "Functions missed by recursive sweep:",recursive_missed,"\n"
  print "\nFunctions in linear and not in recursive:",linear_not_rec
  print "\nFunctions in recursive and not in linear:",rec_not_linear
  print "\nFalse positives for linear sweep:",linear_false_pos
  print "\nFalse positives for recursive descent:",recursive_false_pos

  #function_printer(linear_static)
  #function_printer(recursive_static)
