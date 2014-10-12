# eventually, this can live in a different process
# or we can break the boundary at static2

from qira_webserver import socketio
from qira_webserver import socket_method
from qira_webserver import app

from flask.ext.socketio import SocketIO, emit

from qira_base import *
import json

# *** STATIC CALLS FROM THE FRONTEND ***

@socketio.on('getnames', namespace='/qira')
@socket_method
def getnames(addrs):
  ret = program.static.get_tags(['name'], map(fhex, addrs))
  send = {}
  for addr in ret:
    send[ghex(addr)] = ret[addr]['name']
  emit('names', send)


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
    rret['address'] = ghex(i)
    ret.append(rret)
  return json.dumps(ret)

@socketio.on('getstaticview', namespace='/qira')
@socket_method
def getstaticview(haddr, flat, flatrange):
  fxn = program.static[fhex(haddr)]['function']
  if fxn == None:
    return

  blocks = []
  for b in fxn.blocks:
    bb = []
    for i in sorted(b.addresses):
      bbb = {'address': ghex(i)}
      bbb['comment'] = program.static[i]['comment']
      bbb['instruction'] = str(program.static[i]['instruction'])
      bbb['dests'] = map(lambda (x,y): (ghex(x), y), program.static[i]['instruction'].dests())
      bb.append(bbb)
    blocks.append(bb)

  emit('function', {'blocks': blocks})

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

def init(lprogram):
  global program
  program = lprogram


