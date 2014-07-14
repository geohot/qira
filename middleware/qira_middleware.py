#!/usr/bin/env python
from qira_log import *
from qira_memory import *
from qira_meteor import *
from qira_binary import *
import threading
import time
import sys
import os

from flask import Flask
from flask.ext.socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

# global state for the program
instructions = {}
pmaps = {}
regs = Memory()
mem = Memory()
maxclnum = 1

# python db

# *** HANDLER FOR qira_log ***
def process(log_entries):
  global instructions, pmaps, regs, mem, maxclnum

  db_changes = []

  for (address, data, clnum, flags) in log_entries:
    if clnum > maxclnum:
      maxclnum = clnum

    # Changes database
    this_change = {'address': address&0xFFFFFFFF, 'type': flag_to_type(flags),
        'size': flags&SIZE_MASK, 'clnum': clnum, 'data': data&0xFFFFFFFF}
    if address in instructions:
      this_change['instruction'] = instructions[address]
    db_changes.append(this_change)

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
    page_base = address & 0xFFFFF000
    if flags & IS_MEM and page_base not in pmaps:
      pmaps[page_base] = "memory"
    if flags & IS_START:
      pmaps[page_base] = "instruction"
  # *** FOR LOOP END ***

  return db_changes


def init():
  global instructions, pmaps, regs, mem, maxclnum
  instructions = {}
  pmaps = {}
  regs = Memory()
  mem = Memory()
  maxclnum = 1
  print "reset program state"

  instructions = objdump_binary()
  mem_commit_base_binary(mem)

  #meteor_init(0)

# ***** after this line is the new server stuff *****

@socketio.on('connect', namespace='/qira')
def connect():
  print "client connected", maxclnum
  emit('maxclnum', maxclnum)
  emit('pmaps', pmaps)

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
      ret.append({"name": REGS[i], "address": i*4, "value": regs.daddr[i*4].fetch(clnum)})
  emit('registers', ret)

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
      socketio.emit('maxclnum', maxclnum, namespace='/qira')
      socketio.emit('pmaps', pmaps, namespace='/qira')

      #print "done %d to %d" % (changes_committed,max_changes)
      print "done", maxclnum
      changes_committed = max_changes

if __name__ == '__main__':
  init()
  t = threading.Thread(target=run_middleware)
  t.start()
  run_socketio()

