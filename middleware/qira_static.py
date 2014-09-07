from qira_base import *
import qira_config
from qira_webserver import socket_method, socketio 
from flask.ext.socketio import SocketIO, emit

# should namespace be changed to static?

# type -- ["int", "float", "string", "pointer"] 
# len -- bytes that go with this one
# name -- name of this address
# comment -- comment on this address
# instruction -- string of this instruction
# flow -- see eda-3 docs
# xrefs -- things that point to this
# code -- 'foo.c:38', from DWARF or hexrays
# semantics -- basic block start, is call, is ret, read regs, write regs
# funclength -- this is the start of a function with length
# scope -- first address in function
# flags -- copied from ida

# handle functions outside this
#   function stack frames
#   decompilation

@socketio.on('gettags', namespace='/qira')
@socket_method
def gettags(start, length):
  start = fhex(start)
  ret = []
  for i in range(start, start+length):
    if len(program.tags[i]) != 0:
      # a bit of a hack, this is so javascript can display it
      program.tags[i]['address'] = ghex(i)
      ret.append(program.tags[i])
  emit('tags', ret)

@socketio.on('getfunc', namespace='/qira')
@socket_method
def getfunc(haddr):
  addr = fhex(haddr)
  if 'scope' not in program.tags[addr]:
    return
  start = program.tags[addr]['scope']
  length = program.tags[fhex(start)]['funclength']
  gettags(start, length)

# used to set names and comments and stuff
@socketio.on('settags', namespace='/qira')
@socket_method
def settags(tags):
  for addr in tags:
    naddr = fhex(addr)
    for i in tags[addr]:
      program.tags[naddr][i] = tags[addr][i]
      print hex(naddr), program.tags[naddr][i]

def init_static(lprogram):
  global program
  program = lprogram

