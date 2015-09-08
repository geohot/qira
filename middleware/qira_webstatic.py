# eventually, this can live in a different process
# or we can break the boundary at static2
# these calls don't have to be included for qira to work

import qira_config

from qira_webserver import socketio
from qira_webserver import socket_method
from qira_webserver import app

from flask import Flask, Response, redirect, request
from flask.ext.socketio import SocketIO, emit

from qira_base import *
import json
import os

def init(lprogram):
  global program
  program = lprogram

# *** STATIC CALLS FROM THE FRONTEND ***

@socketio.on('getnames', namespace='/qira')
@socket_method
def getnames(addrs):
  ret = program.static.get_tags(['name'], map(fhex, addrs))
  send = {}
  for addr in ret:
    send[ghex(addr)] = ret[addr]['name']
  emit('names', send)

@app.route('/hasstatic', methods=["GET"])
def hasstatic():
  return str(qira_config.WITH_STATIC)

# TODO: this is a shitty function
@app.route('/gettagsa', methods=["POST"])
@socket_method
def gettagsa():
  arr = json.loads(request.data)
  ret = []
  for i in arr:
    i = fhex(i)

    # always return them all
    # a bit of a hack, this is so javascript can display it
    rret = {}
    for tags in ['name', 'comment']:
      rret[tags] = program.static[i][tags]
    if 'function' in program.static[i] and (program.static[i]['function'].start == i):
      rret['function'] = True
      rret['nargs'] = program.static[i]['function'].nargs
    rret['address'] = ghex(i)
    ret.append(rret)
  return json.dumps(ret)

@socketio.on('gotoname', namespace='/qira')
@socket_method
def gotoname(name):
  addr = program.static.get_address_by_name(name)
  if addr != None:
    emit('setiaddr', ghex(addr))

@socketio.on('settags', namespace='/qira')
@socket_method
def settags(tags):
  for addr in tags:
    naddr = fhex(addr)
    for i in tags[addr]:
      program.static[naddr][i] = tags[addr][i]

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

# currently if we aren't using static, we don't want to draw the staticview
# or be able to makefunction

if qira_config.WITH_STATIC:
  @socketio.on('getstaticview', namespace='/qira')
  @socket_method
  def getstaticview(haddr, flat, flatrange):
    def copy_fields(bbb, stat):
      bbb['type'] = stat['type']
      bbb['comment'] = stat['comment']
      if 'instruction' in stat:
        bbb['instruction'] = str(stat['instruction'])

    fxn = program.static[fhex(haddr)]['function']
    if fxn == None or flat == True:
      addr = fhex(haddr)

      # not a function, return flat view
      ret = []
      # find backward
      i = addr
      while len(ret) != abs(flatrange[0]):
        did_append = False
        # search up to 256 back
        for j in range(1, 256):
          if 'len' in program.static[i-j] and program.static[i-j]['len'] == j:
            i -= j
            bbb = {'address': ghex(i)}
            bbb['bytes'] = map(ord, program.static.memory(i, j))
            ret.append(bbb)
            did_append = True
            break
        if not did_append:
          i -= 1
          bbb = {'address': ghex(i)}
          bbb['bytes'] = map(ord, program.static.memory(i, 1))
          ret.append(bbb)
      ret = ret[::-1]

      # find forward
      i = addr
      while len(ret) != abs(flatrange[0]) + flatrange[1]:
        bbb = {'address': ghex(i)}
        #print program.tags[i]
        if 'len' in program.static[i]:
          l = program.static[i]['len']
          if l == 0:
            l = 1
        else:
          l = 1
        bbb['bytes'] = map(ord, program.static.memory(i, l))
        i += l
        ret.append(bbb)

      for bbb in ret:
        a = fhex(bbb['address'])
        copy_fields(bbb, program.static[a])
        # dests?

      emit('flat', ret)
    else:
      blocks = []
      for b in fxn.blocks:
        bb = []
        for i in sorted(b.addresses):
          bbb = {'address': ghex(i)}
          copy_fields(bbb, program.static[i])
          bbb['dests'] = map(lambda (x,y): (ghex(x), y), program.static[i]['instruction'].dests())
          bb.append(bbb)
        blocks.append(bb)

      emit('function', {'blocks': blocks})

  @socketio.on('make', namespace='/qira')
  @socket_method
  def make(typ, iaddr):
    iaddr = fhex(iaddr)
    print "*** make",typ,"at",ghex(iaddr)
    if typ == 'function':
      program.static.analyzer.make_function_at(program.static, iaddr)
    elif typ == 'code':
      junk = program.static[iaddr]['instruction']
    elif typ == 'data':
      program.static[iaddr]['type'] = 'data'
      if program.static[iaddr]['len'] == 1:
        program.static[iaddr]['len'] = 2
      elif program.static[iaddr]['len'] == 2:
        program.static[iaddr]['len'] = 4
      else:
        program.static[iaddr]['len'] = 1
    elif typ == 'string':
      # get length of string
      eaddr = iaddr
      try:
        while program.static.memory(eaddr, 1)[0] != '\x00':
          eaddr += 1
      except:
        pass
      strlen = eaddr-iaddr
      if strlen == 0:
        return
      mstr = program.static.memory(iaddr, strlen)
      mstr = ''.join(filter(str.isalnum, mstr))

      program.static[iaddr]['type'] = 'string'
      program.static[iaddr]['len'] = strlen
      program.static[iaddr]['name'] = "a"+mstr
    elif typ == 'undefined':
      del program.static[iaddr]['len']
      del program.static[iaddr]['type']
      del program.static[iaddr]['instruction']


