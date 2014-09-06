from qira_base import *
import qira_config
from qira_webserver import socket_method, socketio 
from flask.ext.socketio import SocketIO, emit

# should namespace be changed to static?

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

