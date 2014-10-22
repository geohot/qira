#!/usr/bin/env python2.7

# NO MORE RADARE
# tags should be dynamically generated
#   like when you request the 'instruction' tag, it triggers the disassembly
#   when you set the 'name' tag, it dedups names, and updates the reverse index
#   when you set the 'scope' tag, it adds it as a member of the function
# so it's a "managed" key value store
# don't worry at all about caching unless things are too slow

# stuff from Program should be moved here
#   this class should contain all of the information about an independent run of the binary
# move the webserver code out of here, and perhaps into qira_webserver


# *** EXISTING TAGS ***
# len -- bytes that go with this one
# name -- name of this address
# comment -- comment on this address
# instruction -- string of this instruction
# arch -- arch of this instruction
# crefs -- code xrefs


# objects are allowed in the key-value store,
#   but they should do something sane for the javascript on repr

# fhex and ghex shouldn't be used
# all addresses are numbers

import collections
import os, sys

import linear
import recursive
import loader
import disasm
import byteweight

import re

# debugging
try:
  from hexdump import hexdump
except:
  pass

# allow for special casing certain tags
class Tags:
  def __init__(self, static, address):
    self.backing = {}
    self.static = static
    self.address = address


  def __contains__(self, tag):
    return tag in self.backing

  def __getitem__(self, tag):
    if tag in self.backing:
      return self.backing[tag]
    else:
      # should reading the instruction tag trigger disasm?
      # and should dests be a seperate tag?
      if tag == "instruction":
        dat = self.static.memory(self.address, 0x10)
        # arch should probably come from the address with fallthrough
        self.backing['instruction'] = disasm.disasm(dat, self.address, self.static['arch'])
        self.backing['len'] = self.backing['instruction'].size()
        return self.backing[tag]
      if tag == "crefs" or tag == "xrefs":
        # crefs has a default value of a new array
        self.backing[tag] = set()
        return self.backing[tag]
      if tag in self.static.global_tags:
        return self.static.global_tags[tag]
      return None

  def __setitem__(self, tag, val):
    if tag == "instruction" and type(val) == str:
      raise Exception("instructions shouldn't be strings")
    if tag == "name":
      # name can change by adding underscores
      val = self.static.set_name(self.address, val)
    self.backing[tag] = val

# the new interface for all things static
# will only support radare2 for now
# mostly tags, except for names and functions
class Static:
  def __init__(self, path, debug=False):
    self.tags = {}
    self.path = path

    # radare doesn't seem to have a concept of names
    # doesn't matter if this is in the python
    self.rnames = {}

    # fall through on an instruction
    # 'arch'
    self.global_tags = {}
    self.global_tags['functions'] = set()
    self.global_tags['blocks'] = set()
    self.global_tags['sections'] = []

    # concept from qira_program
    self.base_memory = {}

    # run the elf loader
    loader.load_binary(self, path)

    self.debug = debug
    print "*** elf loaded"

  # this should be replaced with a
  def set_name(self, address, name):
    if name not in self.rnames:
      self.rnames[name] = address
    else:
      # add underscore if name already exists
      return self.set_name(address, name+"_")
    return name

  def _auto_update_name(self, address, name):
    '''modifies the name of address based on data from analyses
       but if we already have a name (from a user or symbols) do nothing'''
    if not self[address]['name']:
      self[address]['name'] = name

  def get_address_by_name(self, name):
    if name in self.rnames:
      return self.rnames[name]
    else:
      return None

  def _insert_names(self,st):
    '''TODO kind of fugly
       takes in a string and replaces things like 0x???????? with
       the name of that address, if it exists
       doesn't make sense to be used externally...'''
    st = str(st)
    m = map(lambda x:int(x,16),re.findall(r"(?<=0x)[0-9a-f]+",st))
    for val in m:
      if self[val]['name']:
        st = st.replace(hex(val),self[val]['name'])
    return st

  # keep the old tags interface
  # names and function data no longer stored here
  # things like xrefs can go here
  # only write functional tags here
  # comment     -- comment on this address
  # len         -- number of bytes grouped with this one
  # instruction -- string of this instruction
  # type        -- unset, 'instruction', 'data', 'string'
  def get_tags(self, filt, addresses=None):
    ret = {}
    if addresses == None:
      # all the addresses
      addresses = self.tags.keys()
    for a in addresses:
      rret = {}
      for f in filt:
        t = self[a][f]
        if t != None:
          rret[f] = t
      if rret != {}:
        ret[a] = rret
    return ret

  def __setitem__(self, address, dat):
    if type(address) is str:
      self.global_tags[address] = dat

  # for a single address
  def __getitem__(self, address):
    if type(address) is str:
      if address in self.global_tags:
        return self.global_tags[address]
      else:
        return None
    if address not in self.tags:
      self.tags[address] = Tags(self, address)
    return self.tags[address]

  # return the memory at address:ln
  # replaces get_static_bytes
  # TODO: refactor this!
  def memory(self, address, ln):
    dat = []
    for i in range(ln):
      ri = address+i
      for (ss, se) in self.base_memory:
        if ss <= ri and ri < se:
          try:
            dat.append(self.base_memory[(ss,se)][ri-ss])
          except:
            return ''.join(dat)
    return ''.join(dat)

  def add_memory_chunk(self, address, dat):
    # sections should have an idea of section permission
    self['sections'].append((address, len(dat)))
    self.base_memory[(address, address+len(dat))] = dat

  def process(self):
    recursive.make_function_at(self, self['entry'])
    main = self.get_address_by_name("main")
    if main != None:
      recursive.make_function_at(self, main)
    print "*** found %d functions" % len(self['functions'])


# *** STATIC TEST STUFF ***

if __name__ == "__main__":
  linear_static = Static(sys.argv[1],debug=True)
  print "arch:",linear_static['arch']

  ##### new (linear sweep) style #####

  function_starts = linear.get_function_starts(linear_static)

  #because main isn't called using BL, we add it manually
  function_starts.add(linear_static.get_address_by_name("main"))

  print "linear technique found {} functions".format(len(function_starts))
  recursive.make_functions_from_starts(linear_static,function_starts)


  for f in sorted(linear_static['functions']):
    print linear_static[f.start]['name'] or hex(f.start), f
    for b in sorted(f.blocks):
      print "  ",b
      for a in sorted(b.addresses):
        print "    ",hex(a),linear_static._insert_names(linear_static[a]['instruction'])

  ##### old (recursive descent) style here #####

  recursive_static = Static(sys.argv[1],debug=True)

  # find main
  main = recursive_static.get_address_by_name("main")
  print "main is at", hex(main)
  recursive.make_function_at(recursive_static, recursive_static['entry'], recurse=True)
  print "recursive descent found %d functions" % len(recursive_static['functions'])
  recursive.make_function_at(recursive_static, main, recurse=True)
  print "recursive descent found %d functions" % len(recursive_static['functions'])

  # function printer
  for f in sorted(recursive_static['functions']):
    print recursive_static[f.start]['name'] or hex(f.start), f
    for b in sorted(f.blocks):
      print "  ",b
      for a in sorted(b.addresses):
        print "    ",hex(a),recursive_static._insert_names(recursive_static[a]['instruction'])

  #print recursive_static['functions']

  #print recursive_static[main]['instruction'], map(hex, recursive_static[main]['crefs'])
  #print recursive_static.get_tags(['name'])
  bw_functions = byteweight.fsi(recursive_static)
  for f in bw_functions:
    print hex(f)
    hexdump(recursive_static.memory(f, 0x20))
