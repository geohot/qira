#!/usr/bin/env python
from qira_log import *
from qira_memory import *
from qira_binary import *
import threading
import time
import sys
import os
from collections import defaultdict

from flask import Flask, Response
from flask.ext.socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

# global state for the program
instructions = {}
pmaps = {}
regs = Memory()
mem = Memory()
maxclnum = 1

# python db has two indexes
#  types are I, r, m
# pydb_addr:  (addr, type) -> [clnums]
# pydb_clnum: (clnum, type) -> [changes]
pydb_addr = defaultdict(list)
pydb_clnum = defaultdict(list)

# *** HANDLER FOR qira_log ***
def process(log_entries):
  global instructions, pmaps, regs, mem, maxclnum, pydb_addr, pydb_clnum

  db_changes = []

  for (address, data, clnum, flags) in log_entries:
    if clnum > maxclnum:
      maxclnum = clnum

    # construct this_change
    this_change = {'address': address, 'type': flag_to_type(flags),
        'size': flags&SIZE_MASK, 'clnum': clnum, 'data': data}
    if address in instructions:
      this_change['instruction'] = instructions[address]

    # Changes database for mongo
    db_changes.append(this_change)

    # update python database
    pytype = flag_to_type(flags)
    pydb_addr[(address, pytype)].append(clnum)
    pydb_clnum[(clnum, pytype)].append(this_change)

    # update local regs and mem database
    # this is somewhat slow...
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

    # for Pmaps
    # shouldn't really send this each time, but it should be smaller anyway
    page_base = (address>>12)<<12
    if flags & IS_MEM and page_base not in pmaps:
      pmaps[page_base] = "memory"
    if flags & IS_START:
      pmaps[page_base] = "instruction"
  # *** FOR LOOP END ***

  return db_changes


def init():
  global instructions, pmaps, regs, mem, maxclnum, pydb_addr, pydb_clnum
  instructions = {}
  pmaps = {}
  regs = Memory()
  mem = Memory()
  maxclnum = 1
  print "reset program state"

  instructions = objdump_binary()
  mem_commit_base_binary(mem)
  print "mem commit done"

  pydb_addr = defaultdict(list)
  pydb_clnum = defaultdict(list)

  #meteor_init(0)

# ***** after this line is the new server stuff *****

@socketio.on('connect', namespace='/qira')
def connect():
  print "client connected", maxclnum
  emit('maxclnum', maxclnum)
  emit('pmaps', pmaps)

@socketio.on('getclnum', namespace='/qira')
def getclnum(m):
  #print "getclnum",m
  if m == None or 'clnum' not in m or 'types' not in m or 'limit' not in m:
    return
  ret = []
  for t in m['types']:
    key = (m['clnum'], t)
    for c in pydb_clnum[key]:
      ret.append(c)
      if len(ret) >= m['limit']:
        break
    if len(ret) >= m['limit']:
      break
  emit('clnum', ret)

@socketio.on('getchanges', namespace='/qira')
def getchanges(m):
  #print "getchanges",m
  if m == None or 'address' not in m or 'type' not in m or m['address'] == None or m['type'] == None:
    return
  key = (m['address'], m['type'])
  emit('changes', {'type': m['type'], 'clnums': pydb_addr[key]})

@socketio.on('getinstructions', namespace='/qira')
def getinstructions(m):
  #print "getinstructions",m
  if m == None or m['clstart'] == None or m['clend'] == None:
    return
  ret = []
  for i in range(m['clstart'], m['clend']):
    key = (i, 'I')
    if key in pydb_clnum:
      ret.append(pydb_clnum[key][0])
  emit('instructions', ret)

@socketio.on('getmemory', namespace='/qira')
def getmemory(m):
  #print "getmemory",m
  if m == None or \
      'clnum' not in m or 'address' not in m or 'len' not in m or \
      m['clnum'] == None or m['address'] == None or m['len'] == None:
    return
  dat = mem.fetch(m['clnum'], m['address'], m['len'])
  ret = {'address': m['address'], 'len': m['len'], 'dat': dat}
  emit('memory', ret)

@socketio.on('getregisters', namespace='/qira')
def getregisters(clnum):
  #print "getregisters",clnum
  if clnum == None:
    return
  # register names shouldn't be here
  # though i'm not really sure where a better place is, qemu has this information
  X86REGS = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP']
  REGS = X86REGS
  ret = []
  for i in range(0, len(REGS)):
    if i*4 in regs.daddr:
      rret = {"name": REGS[i], "address": i*4, "value": regs.daddr[i*4].fetch(clnum), "regactions": ""}
      if clnum in pydb_addr[(i*4, 'R')]:
        rret['regactions'] += " regread"
      if clnum in pydb_addr[(i*4, 'W')]:
        rret['regactions'] += " regwrite"
      ret.append(rret)
  emit('registers', ret)

@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
def serve(path):
  # best security?
  if ".." in path:
    return
  webstatic = os.path.dirname(os.path.realpath(__file__))+"/../webstatic/"

  ext = path.split(".")[-1]

  if ext == 'css':
    path = "qira.css"

  dat = open(webstatic+path).read()
  if ext == 'js' and not path.startswith('client/compatibility/') and not path.startswith('packages/'):
    dat = "(function(){"+dat+"})();"

  if ext == 'js':
    return Response(dat, mimetype="application/javascript")
  elif ext == 'css':
    return Response(dat, mimetype="text/css")
  else:
    return Response(dat, mimetype="text/html")



def run_socketio():
  print "starting socketio server..."
  socketio.run(app, port=3002)

def run_middleware():
  print "starting QIRA middleware"
  changes_committed = 1

  # run loop run
  while 1:
    time.sleep(0.05)
    max_changes = get_log_length(LOGFILE)
    if max_changes < changes_committed:
      print "RESTART..."
      init()
      changes_committed = 1
    if changes_committed < max_changes:
      sys.stdout.write("going from %d to %d..." % (changes_committed,max_changes))
      sys.stdout.flush()
      log = read_log(LOGFILE, changes_committed, max_changes - changes_committed)
      sys.stdout.write("read..."); sys.stdout.flush()
      db_changes = process(log)

      # push to mongodb
      #sys.stdout.write("mongoing..."); sys.stdout.flush()
      #db_push_changes(db_changes)

      # push to all connected websockets
      sys.stdout.write("socket..."); sys.stdout.flush()
      sys.stdout.flush()
      socketio.emit('pmaps', pmaps, namespace='/qira')

      # this must happen last
      socketio.emit('maxclnum', maxclnum, namespace='/qira')

      #print "done %d to %d" % (changes_committed,max_changes)
      print "done", maxclnum
      changes_committed = max_changes

if __name__ == '__main__':
  init()
  t = threading.Thread(target=run_middleware)
  t.start()
  run_socketio()

