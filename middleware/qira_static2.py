#!/usr/bin/env python2.7

# qira_static2 only supports radare

from qira_base import *
import qira_config
import collections
import os, sys

# webserver imports
import json
from qira_webserver import socket_method, socketio, app
from flask import request
from flask.ext.socketio import SocketIO, emit

# radare2 is best static, and the only one we support
# if we want QIRA to work without it,
#   this file import must gate on qira_config.WITH_RADARE
from r2.r_core import RCore

# allow for special casing certain tags
class Tags:
  def __init__(self):
    self.backing = {}

  def __getitem__(self, address):
    return self.backing[address]

  def __setitem__(self, address, val):
    self.backing[address] = val

# the new interface for all things static
# will only support radare2 for now
# mostly tags, except for names and functions
class Static:
  # called with a qira_program.Program
  def __init__(self, program):
    self.tags = collections.defaultdict(Tags)
    self.program = program

    # radare doesn't seem to have a concept of names
    # doesn't matter if this is in the python
    self.names = {}
    self.rnames = {}

    # init radare
    self.core = RCore()
    self.load_binary(program.program)

  def load_binary(self, path):
    desc = self.core.io.open(path, 0, 0)
    if desc == None:
      print "*** RBIN LOAD FAILED"
      return
    self.core.bin.load(path, 0, 0, 0, desc.fd, False)

    # why do i need to do this?
    info = self.core.bin.get_info()
    self.core.config.set("asm.arch", info.arch);
    self.core.config.set("asm.bits", str(info.bits));

    # you have to file_open to make analysis work
    self.core.file_open(path, False, 0)
    self.core.bin_load("", 0)

    # i believe you can call this multiple times
    self.run_analysis()

  def run_analysis(self):
    # run analysis
    self.core.anal_all()

    # sadly the analyzer jacks stdout and stderr
    # flush bullshit and fix ctrl-c
    sys.stderr.flush()
    sys.stdout.flush()
    print ""
    import signal
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # get names
    name_count = 0
    for s in self.core.bin.get_symbols():
      self.set_name(s.vaddr, s.name)
      name_count += 1

    # get functions
    fcn_count = 0
    for f in self.core.anal.get_fcns():
      #print hex(f.addr), f.name
      #print f.get_bbs()
      fcn_count += 1

    # get other things here?
    print "static found %d names and %d functions" % (name_count, fcn_count)

  # return a dictionary of addresses:names
  # don't allow two things to share a name
  # not even worth trying to fit into the tags interface
  def get_names(self, addresses):
    ret = {}
    for a in addresses:
      if a in self.names:
        ret[a] = self.names[a]
    return ret

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
    return self.tags[address]

  # return the memory at address:ln
  # replaces get_static_bytes
  def get_memory(self, address, ln):
    pass

  # returns a graph of the blocks and the flow for a function
  # this is a divergence from the old tags approach
  # return None if not in function
  def get_function_blocks(self, address):
    # this is broken
    #fcn = self.core.anal.get_fcn_at(address)

    fcn = None
    for f in self.core.anal.get_fcns():
      if f.addr <= address and address <= f.addr+f.size:
        fcn = f
    if fcn == None:
      print "function not found"
      return None
    # how to detect if not in function?
    for bb in fcn.get_bbs():
      print "block %x-%x ninstr: %d jump:%x fail:%x" % (bb.addr, bb.addr+bb.size, bb.ninstr, bb.jump, bb.fail)

  # things to actually drive the static analyzer
  # runs the recursive descent parser at address
  def make_code_at(self, address):
    pass

  def make_function_at(self, address):
    pass

# *** CALLS FROM THE FRONTEND ***

@socketio.on('getnames', namespace='/qira')
@socket_method
def getnames(addrs):
  ret = static.get_names(map(fhex, addrs))
  send = {}
  for addr in ret:
    send[ghex(addr)] = ret[addr]
  emit('names', send)

@socketio.on('gotoname', namespace='/qira')
@socket_method
def gotoname(name):
  addr = static.get_address_by_name(name)
  if addr != None:
    emit('setiaddr', ghex(addr))

@socketio.on('settags', namespace='/qira')
@socket_method
def settags(tags):
  for addr in tags:
    naddr = fhex(addr)
    for i in tags[addr]:
      if i == 'name':
        static.set_name(addr, tags[addr][i])
      else:
        static[naddr][i] = tags[addr][i]

# *** STATIC INIT STUFF ***

def init_static(program):
  global static
  static = Static(program)
  return static

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


