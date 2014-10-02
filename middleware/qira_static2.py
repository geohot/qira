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

from qira_base import *
import qira_config
import collections
import os, sys

# webserver imports
import json
from qira_webserver import socket_method, socketio, app
from flask import request
from flask.ext.socketio import SocketIO, emit

# allow for special casing certain tags
class Tags:
  def __init__(self, static, address):
    self.backing = {}
    self.static = static
    self.address = address

  def __getitem__(self, tag):
    return self.backing[tag]

  def __setitem__(self, tag, val):
    if tag == "name":
      self.static.set_name(self.address, val)
    self.backing[tag] = val

# the new interface for all things static
# will only support radare2 for now
# mostly tags, except for names and functions
class Static:
  # called with a qira_program.Program
  def __init__(self, program):
    self.tags = {}
    self.program = program

    # radare doesn't seem to have a concept of names
    # doesn't matter if this is in the python
    self.names = {}
    self.rnames = {}

    # init radare
    self.load_binary(program.program)

  def load_binary(self, path):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.relocation import RelocationSection
    elf = ELFFile(open(path))
    ncount = 0
    for section in elf.iter_sections():
      if isinstance(section, RelocationSection):
        symtable = elf.get_section(section['sh_link'])
        for rel in section.iter_relocations():
          symbol = symtable.get_symbol(rel['r_info_sym'])
          #print rel, symbol.name
          if rel['r_offset'] != 0 and symbol.name != "":
            self[rel['r_offset']]['name'] = "__"+symbol.name
            ncount += 1
      if isinstance(section, SymbolTableSection):
        for nsym, symbol in enumerate(section.iter_symbols()):
          if symbol['st_value'] != 0 and symbol.name != "" and symbol['st_info']['type'] == "STT_FUNC":
            #print symbol['st_value'], symbol.name
            self[symbol['st_value']]['name'] = symbol.name
            ncount += 1
    print "** found %d names" % ncount

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
      self.names[address] = name
      self.rnames[name] = address
    else:
      # add underscore if name already exists
      self.set_name(address, name+"_")

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
  def get_memory(self, address, ln):
    pass

  # returns a graph of the blocks and the flow for a function
  # this is a divergence from the old tags approach
  # return None if not in function
  def get_function_blocks(self, address):
    pass

  # things to actually drive the static analyzer
  # runs the recursive descent parser at address
  def make_code_at(self, address):
    pass

  def make_function_at(self, address):
    pass

# *** STATIC INIT STUFF ***

if __name__ == "__main__":
  class Program:
    def __init__(self, f):
      self.program = f

  program = Program(sys.argv[1])
  static = Static(program)

  # find main
  main = static.get_address_by_name("main")
  print "main is at", ghex(main)

  print static.get_function_blocks(main)


