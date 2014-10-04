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

import disasm
import loader
import Queue

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

  def __getitem__(self, tag):
    # should reading the instruction tag trigger disasm?
    """
    if tag == "instruction":
      dat = self.static.memory(self.address, 0x10)
      return disasm.disasm(dat, self.address, self['arch'])
    """

    if tag in self.backing:
      return self.backing[tag]
    else:
      if tag == "crefs":
        # crefs has a default value of a new array
        self.backing['crefs'] = []
        return self.backing['crefs']
      if tag in static.global_tags:
        return static.global_tags[tag]
      return None

  def __setitem__(self, tag, val):
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

    # concept from qira_program
    self.base_memory = {}

    # run the elf loader
    loader.load_binary(self, path)

    self.debug = debug

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

  def _insert_names(self,st):
    '''TODO kind of fugly
       takes in a string and replaces things like 0x???????? with
       the name of that address, if it exists'''
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
        t = self.tags[a][f]
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
    self.base_memory[(address, address+len(dat))] = dat

  # things to actually drive the static analyzer
  # runs the recursive descent parser at address
  # how to deal with block groupings?
  def make_code_at(self, address):
    block_starts = set([address])
    def disassemble(address):
      raw = self.memory(address, 0x10)
      d = disasm.disasm(raw, address, self[address]['arch'])
      self[address]['instruction'] = d
      self[address]['len'] = d.size()
      for (c,flag) in d.dests():
        #if we aren't just the next instruction, we have an explicit xref
        if c != address + d.size():
          #destination of a call is a function
          if d.is_call():
            self[c]['function'] = True

          #if we don't have a name, update our name
          if not self[c]['name']:
            self[c]['name'] = "%s_%x"%("sub" if d.is_call() else "loc",c)

          self[c]['crefs'].append(address)
          block_starts.add(c)

        #if we come after a jump and are an implicit xref, we are the start
        #of a new block
        elif d.is_jump():
          block_starts.add(c)
      return d.dests()

    # recursive descent pass
    pending = Queue.Queue()
    done = set()
    pending.put(address)
    while not pending.empty():
      dests = disassemble(pending.get())
      for (d,flag) in dests:
        if d not in done:
          pending.put(d)
          done.add(d)
  
    #print map(hex, done)

    # block finding pass
    blocks = []
    for b in block_starts:
      address = b
      i = self[address]['instruction']
      while not i.is_ending() and i.size() != 0:
        if address + i.size() in block_starts:
          break
        address += i.size()
        i = self[address]['instruction']
      blocks.append((b, address))

    #print out basic blocks in simple disassembly view
    if self.debug:
      for b in sorted(blocks,key=lambda b:b[0]):
        print "  -------  %s [%s] -------"%(self[b[0]]['name']," ".join(map(hex,self[b[0]]['crefs'])))
        for a in range(b[0], b[1]+1):
          if self[a]['instruction'] != None:
            print "  ",hex(a),self._insert_names(self[a]['instruction'])

        print "  -------  %s [%s] -------"%(hex(b[1]), \
         " ".join( map(lambda x:hex(x[0]),self[b[1]]['instruction'].dests()) ))
        print

# *** STATIC TEST STUFF ***

if __name__ == "__main__":
  static = Static(sys.argv[1],debug=True)
  print "arch:",static['arch']

  # find main
  main = static.get_address_by_name("main")
  print "main is at", hex(main)
  static.make_code_at(main)

  #print static[main]['instruction'], map(hex, static[main]['crefs'])
  #print static.get_tags(['name'])


