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
import re

sys.path.append("../middleware")
import qira_config

from model import Tags

# debugging
try:
  from hexdump import hexdump
except:
  pass


# the new interface for all things static
# will only support radare2 for now
# mostly tags, except for names and functions
class Static:
  def __init__(self, path, debug=False):
    self.tags = {}
    self.path = path
    self.r2core = None

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

    if qira_config.STATIC_ENGINE == "r2":
      sys.path.append(os.path.join(qira_config.BASEDIR, "static2", "r2"))
      import r2pipe 
      import loader 
      import analyzer
      self.r2core = r2pipe.r2pipe(path)
      # capstone is not working ok yet, so using udis for now
      self.r2core.cmd("e asm.arch=x86.udis")
      self.r2core.cmd("aa;af @ main")
    else:
      # run the elf loader
      sys.path.append(os.path.join(qira_config.BASEDIR, "static2", "builtin"))
      import loader
      import analyzer
    self.analyzer = analyzer
    loader.load_binary(self)

    self.debug = debug
    print "*** elf loaded"

  # this should be replaced with a 
  def set_name(self, address, name):
    if name not in self.rnames:
      self.rnames[name] = address
    elif address != self.rnames[name]:
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

      # hack for "RuntimeError: dictionary changed size during iteration"
      for (ss, se) in self.base_memory.keys():
        if ss <= ri and ri < se:
          try:
            dat.append(self.base_memory[(ss,se)][ri-ss])
            break
          except:
            return ''.join(dat)
    return ''.join(dat)

  def add_memory_chunk(self, address, dat):
    #print "add section",hex(address),len(dat)
    # check for dups
    for (laddress, llength) in self.base_memory:
      if address == laddress:
        if self.base_memory[(laddress, llength)] != dat:
          print "*** WARNING, changing section",hex(laddress),llength
        return
    
    # sections should have an idea of section permission
    self['sections'].append((address, len(dat)))
    self.base_memory[(address, address+len(dat))] = dat

  def process(self):
    self.analyzer.analyze_functions(self)
    print "*** found %d functions" % len(self['functions'])


# *** STATIC TEST STUFF ***

if __name__ == "__main__":
  static = Static(sys.argv[1],debug=True)
  print "arch:",static['arch']

  # find main
  static.process()
  """
  main = static.get_address_by_name("main")
  print "main is at", main
  recursive.make_function_at(static, static['entry'])
  print "found %d functions" % len(static['functions'])
  recursive.make_function_at(static, main)
  print "found %d functions" % len(static['functions'])
  """


  # function printer
  for f in sorted(static['functions']):
    print static[f.start]['name'] or hex(f.start), f
    for b in sorted(f.blocks):
      print "  ",b
      for a in sorted(b.addresses):
        print "    ",hex(a),static._insert_names(static[a]['instruction'])

  #print static['functions']

  #print static[main]['instruction'], map(hex, static[main]['crefs'])
  #print static.get_tags(['name'])
  #bw_functions = byteweight.fsi(static)
  #for f in bw_functions:
    #print hex(f)
    #hexdump(static.memory(f, 0x20))


