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

# fhex and ghex shouldn't be used
# all addresses are numbers

import collections
import os, sys

import disasm
import loader

# allow for special casing certain tags
class Tags:
  def __init__(self, static, address):
    self.backing = {}
    self.static = static
    self.address = address

  def __getitem__(self, tag):
    if tag == "instruction":
      return disasm(self.static.memory(self.address, self['len']), self.address, self['arch'])
    return self.backing[tag]

  def __setitem__(self, tag, val):
    if tag == "name":
      # name can change by adding underscores
      val = self.static.set_name(self.address, val)
    self.backing[tag] = val

# the new interface for all things static
# will only support radare2 for now
# mostly tags, except for names and functions
class Static:
  def __init__(self, path):
    self.tags = {}
    self.path = path

    # radare doesn't seem to have a concept of names
    # doesn't matter if this is in the python
    self.names = {}
    self.rnames = {}

    # concept from qira_program
    self.base_memory = {}

    # run the elf loader
    loader.load_binary(self, path)

  # return a dictionary of addresses:names
  # don't allow two things to share a name
  # not even worth trying to fit into the tags interface
  def get_names(self, addresses):
    ret = {}
    for a in addresses:
      if a in self.names:
        ret[a] = self.names[a]
    return ret

  # this should be replaced with a 
  def set_name(self, address, name):
    if name not in self.rnames:
      self.rnames[name] = address
    else:
      # add underscore if name already exists
      return self.set_name(address, name+"_")
    return name

  def get_address_by_name(self, name):
    if name in self.rnames:
      return self.rnames[name]
    else:
      return None

  # keep the old tags interface
  # names and function data no longer stored here
  # things like xrefs can go here
  # only write functional tags here
  # comment     -- comment on this address
  # len         -- number of bytes grouped with this one
  # instruction -- string of this instruction
  # type        -- unset, 'instruction', 'data', 'string'
  def get_tags(self, addresses, filt=None):
    ret = {}
    for a in addresses:
      ret[a] = {}
      for t in self.tags[a]:
        if filt == None or t in filt:
          ret[a][t] = self.tags[a][t]
    return ret
  
  # for a single address
  def __getitem__(self, address):
    if address not in self.tags:
      self.tags[address] = Tags(self, address)
    return self.tags[address]

  # return the memory at address:ln
  # replaces get_static_bytes
  def memory(self, address, ln):
    for i in range(ln):
      ri = address+i
      for (ss, se) in self.base_memory:
        if ss <= ri and ri < se:
          try:
            dat[i] = ord(self.base_memory[(ss,se)][ri-ss])
          except:
            pass

  def add_memory_chunk(self, address, dat):
    self.base_memory[(address, address+len(dat))] = dat

  # things to actually drive the static analyzer
  # runs the recursive descent parser at address
  def make_code_at(self, address):
    pass


# *** STATIC INIT STUFF ***

if __name__ == "__main__":
  static = Static(sys.argv[1])

  # find main
  main = static.get_address_by_name("main")
  print "main is at", hex(main)

