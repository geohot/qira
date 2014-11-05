# *** STATIC TEST STUFF ***

from static2 import *
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

def test(fns,stripped=[],use_libida=False):
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
  if use_libida:
    d['i386_missed_ida'] = 0
    d['x86-64_missed_ida'] = 0

  #each argument is a set of addresses and names (we take the intersection by address)
  #functions1-functions2
  def get_missed(functions1,functions2):
    f1_addresses = set(x[0] for x in functions1)
    f2_addresses = set(x[0] for x in functions2)
    return f1_addresses-f2_addresses
    #return set(x[1] for x in functions1 if x[0] in (f1_addresses-f2_addresses))

  def static_to_function_set(static):
    return set((f.start,static[f.start]['name']) for f in static['functions'])

  num_fns = len(fns)

  for i,fn in enumerate(fns):
    print "[{}/{}] {}".format(i+1,num_fns,fn)
    linear_static = test_linear(fn)
    recursive_static = test_recursive(fn)
    arch = linear_static['arch']

    if use_libida:
      if arch in ["i386","x86-64"]: #archs supported in demo - incorporate real libida?
        stripped_fn = stripped[i] #this is so ugly; it can be done better
        ida.init_with_binary(stripped_fn)
        ida_functions = get_functions_from_ida_tags(ida.fetch_tags())
      else:
        print "ida not available for this binary"

    #test_byteweight(Static(fn,debug=True))

    real_functions = linear_static['debug_functions']
    linear_functions = static_to_function_set(linear_static)
    recursive_functions = static_to_function_set(recursive_static)

    num_real_functions = len(real_functions)

    if arch == "i386":
      d['i386_total_fns'] += num_real_functions
      d['i386_missed_lin'] += len(get_missed(real_functions,linear_functions))
      d['i386_missed_rec'] += len(get_missed(real_functions,recursive_functions))
      if use_libida: d['i386_missed_ida'] += len((set(x[0] for x in real_functions))-ida_functions)
    elif arch == "x86-64":
      d['x86-64_total_fns'] += num_real_functions
      d['x86-64_missed_lin'] += len(get_missed(real_functions,linear_functions))
      d['x86-64_missed_rec'] += len(get_missed(real_functions,recursive_functions))
      if use_libida: d['x86-64_missed_ida'] += len((set(x[0] for x in real_functions))-ida_functions)
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
    if use_libida: print "Functions found by IDA:               {}".format(d['i386_total_fns']-d['i386_missed_lin'])
    print "Functions found by linear sweep:      {}".format(d['i386_total_fns']-d['i386_missed_lin'])
    print "Functions found by recursive descent: {}".format(d['i386_total_fns']-d['i386_missed_rec'])

  if d['x86-64_total_fns'] != 0:
    print "\nx86-64:"
    print "Total functions (from symbols):       {}".format(d['x86-64_total_fns'])
    if use_libida: print "Functions found by IDA:               {}".format(d['i386_total_fns']-d['i386_missed_lin'])
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

def get_functions_from_ida_tags(tags):
  return {int(tags[addr]['scope'],16) for addr in tags if 'scope' in tags[addr]}

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="By default, tests all applicable files in ../tests/")
  parser.add_argument('--file', help="a single file to test (must have symbols)")
  parser.add_argument('--prepare-for-ida', dest='prepare_ida', action='store_true',
                      help="prepare directory of stripped binaries for IDA")
  parser.add_argument('--become-ida',dest="use_libida",action='store_true',
                      help='use libida.so directly, requires 32bit python')
  args = parser.parse_args()

  if args.use_libida:
    import ida

  if args.file is not None:
    fns = [args.file]
  else:
    fns = [os.path.join(path,fn) for path,_,fns in os.walk("../tests/") for fn in fns]

  #get nonstripped elf binaries (this is hacky)
  nonstripped_info = []
  for fn in fns:
    info = subprocess.check_output(["file",fn])
    if "ELF" in info and "not stripped" in info:
      nonstripped_info.append((fn,info))

  #strip files if we're using IDA
  stripped = []
  if args.prepare_ida or args.use_libida:
    #make directory of stripped binaries
    subprocess.call(["mkdir","-p","stripped"])
    #handle errors here?
    for fn,info in nonstripped_info:
      raw_fn = fn.split("/")[-1]
      stripped_fn = "stripped/"+raw_fn
      cmd1 = ["cp",fn,stripped_fn]
      #need binutils-multiarch to work on ARM
      cmd2 = ["strip",stripped_fn]
      #print " ".join(cmd1)
      #print " ".join(cmd2)
      subprocess.call(cmd1) #check if these exist
      subprocess.call(cmd2)
      stripped.append(stripped_fn)

      if not args.use_libida:
        ida_cmd = "idaw64" if "x86-64" in info else "idaw"
        print "{} -A -OIDAPython:get_ida_info.py {}".format(ida_cmd,stripped_fn)
  nonstripped = [fn for fn,_ in nonstripped_info]

  test(nonstripped,stripped,use_libida=args.use_libida)
