from qira_base import *
import qira_config
from qira_webserver import socket_method, socketio, app
from flask import request
from flask.ext.socketio import SocketIO, emit
import os
import json

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

@app.route('/gettagsa', methods=["POST"])
def gettagsa():
  arr = json.loads(request.data)
  ret = []
  for i in arr:
    i = fhex(i)
    # always return them all
    # a bit of a hack, this is so javascript can display it
    program.tags[i]['address'] = ghex(i)
    ret.append(program.tags[i])
  return json.dumps(ret)

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
  emit('tags', ret, True)

@socketio.on('getstaticview', namespace='/qira')
@socket_method
def getstaticview(haddr, flat, flatrange):
  # disable this to disable static
  if not qira_config.WITH_STATIC:
    return

  addr = fhex(haddr)
  if flat or 'scope' not in program.tags[addr]:
    # not a function, return flat view
    ret = []
    # find backward
    i = addr
    while len(ret) != abs(flatrange[0]):
      did_append = False
      # search up to 256 back
      for j in range(1, 256):
        if 'len' in program.tags[i-j] and program.tags[i-j]['len'] == j:
          i -= j
          program.tags[i]['address'] = ghex(i)
          ret.append(program.tags[i])
          did_append = True
          break
      if not did_append:
        i -= 1
        program.tags[i]['address'] = ghex(i)
        ret.append(program.tags[i])
    ret = ret[::-1]
    # find forward
    i = addr
    while len(ret) != abs(flatrange[0]) + flatrange[1]:
      program.tags[i]['address'] = ghex(i)
      ret.append(program.tags[i])
      #print program.tags[i]
      if 'len' in program.tags[i]:
        i += program.tags[i]['len']
      else:
        i += 1
    emit('tags', ret, False)
  else:
    # function
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
      print hex(naddr), i, program.tags[naddr][i]

# dot as a service
@app.route('/dot', methods=["POST"])
def graph_dot():
  req = request.data
  #print "DOT REQUEST", req
  f = open("/tmp/in.dot", "w")
  f.write(req)
  f.close()
  os.system("dot /tmp/in.dot > /tmp/out.dot")
  ret = open("/tmp/out.dot").read()
  #print "DOT RESPONSE", ret
  return ret

def init_static(lprogram):
  global program
  program = lprogram

