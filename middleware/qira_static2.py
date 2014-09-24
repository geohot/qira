#!/usr/bin/env python2.7
from qira_base import *
import qira_config
import collections

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

  # return a dictionary of addresses:names
  # don't allow two things to share a name
  # not even worth trying to fit into the tags interface
  def get_names(self, addresses):
    pass

  def set_name(self, address, name):
    pass

  def get_address_by_name(self, name):
    pass

  # keep the old tags interface
  # names and function data no longer stored here
  # things like xrefs can go here
  # only write functional tags here
  # comment     -- comment on this address
  # len         -- number of bytes grouped with this one
  # instruction -- string of this instruction
  # type        -- unset, 'instruction', 'data', 'string'
  def get_tags(self, addresses, filt=None):
    pass
  
  # for a single address
  def __getitem__(self, address):
    return self.tags[address]

  # returns a graph of the blocks and the flow for a function
  # this is a divergence from the old tags approach
  def get_function_blocks(self, address):
    pass

  # return the memory at address:ln
  # replaces get_static_bytes
  def get_memory(self, address, ln):
    pass

  # return first address of function if this address is in a function
  def in_function(self, address):
    pass

  # things to actually drive the static analyzer
  def make_code_at(self, address):
    pass

  def make_function_at(self, address):
    pass


