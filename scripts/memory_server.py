from qira_log import *
from flask import Flask
from flask.ext.socketio import SocketIO, emit
import base64

class Address:
  def __init__(this):
    this.backing = {}

  def fetch(this, clnum):
    # use binary search lol
    while clnum >= 0:
      if clnum in this.backing:
        return this.backing[clnum]
      clnum -= 1
    # if the change is before it was written to
    return 0   # canary

  def commit(this, clnum, dat):
    this.backing[clnum] = dat

class Memory:
  def __init__(this):
    this.daddr = {}
  def fetch(this, clnum, addr, l):
    ret = []
    for i in range(addr, addr+l):
      if i in this.daddr:
        ret.append(chr(this.daddr[i].fetch(clnum)))
      else:
        ret.append("\xAA")   # best canary value
    return ''.join(ret)
  def commit(this, clnum, addr, dat):
    if addr not in this.daddr:
      this.daddr[addr] = Address()
    this.daddr[addr].commit(clnum, dat)

regs = Memory()
mem = Memory()

def init():
  dat = read_log("/tmp/qira_log")
  for (address, data, clnum, flags) in dat:
    if flags & IS_WRITE and flags & IS_MEM:
      size = flags & SIZE_MASK
      # support big endian
      for i in range(0, size/8):
        mem.commit(clnum, address+i, data & 0xFF)
        data >>= 8
    elif flags & IS_WRITE:
      size = flags & SIZE_MASK
      # support big endian
      regs.commit(clnum, address, data)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

@socketio.on('getmemory')
def event(m):
  if m['clnum'] == None or m['address'] == None or m['len'] == None:
    return
  print "my event ",m
  dat = mem.fetch(m['clnum'], m['address'], m['len'])
  emit('memory', {'address': m['address'], 'raw': base64.b64encode(dat)})

@socketio.on('getregisters')
def regevent(m):
  if m['clnum'] == None:
    return
  # register names shouldn't be here
  X86REGS = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP']
  ret = {}
  for i in range(0, len(X86REGS)):
    ret[X86REGS[i]] = regs.daddr[i*4].fetch(m['clnum'])
  emit('registers', ret)

if __name__ == '__main__':
  init()
  print "init done"
  socketio.run(app, port=3002)

