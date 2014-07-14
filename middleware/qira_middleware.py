#!/usr/bin/env python
from qira_log import *
from qira_memory import *
from qira_meteor import *
from qira_binary import *
import time
import sys
import os

# global state for the program
instructions = {}
pmaps = {}
regs = Memory()
mem = Memory()
maxclnum = 1

# *** HANDLER FOR qira_log ***
def process(log_entries):
  global instructions, pmaps, regs, mem, maxclnum

  db_changes = []
  new_pmaps = pmaps.copy()

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
    page_base = address & 0xFFFFF000
    if flags & IS_MEM and page_base not in new_pmaps:
      new_pmaps[page_base] = "memory"
    if flags & IS_START:
      new_pmaps[page_base] = "instruction"
  # *** FOR LOOP END ***

  # push new pmaps
  db_pmaps = []
  for i in new_pmaps:
    if i not in pmaps or pmaps[i] != new_pmaps[i]:
      db_pmaps.append({"address": i, "type": new_pmaps[i]})

  # *** actually push to db ***
  #write_memdb(regs, mem)
  #db_push(db_changes, db_pmaps)

def init():
  global instructions, pmaps, regs, mem
  global meteor_pid
  instructions = {}
  pmaps = {}
  regs = Memory()
  mem = Memory()
  print "reset program state"

  instructions = objdump_binary()
  mem_commit_base_binary(mem)

  #write_memdb(regs, mem)
  #meteor_init(0)


# ***** after this line is the new server stuff *****

from flask import Flask
from flask.ext.socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

@socketio.on('connect', namespace='/qira')
def connect():
  print "client connected"
  emit('maxclnum', maxclnum)

@socketio.on('getmemory', namespace='/qira')
def getmemory(m):
  print "getmemory",m
  if m == None or \
      'clnum' not in m or 'address' not in m or 'len' not in m or \
      m['clnum'] == None or m['address'] == None or m['len'] == None:
    return
  dat = mem.fetch(m['clnum'], m['address'], m['len'])
  ret = {'address': m['address'], 'len': m['len'], 'dat': dat}
  emit('memory', ret)

@socketio.on('getregisters', namespace='/qira')
def getregisters(clnum):
  print "getregisters",clnum
  if clnum == None:
    return
  # register names shouldn't be here
  X86REGS = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP']
  REGS = X86REGS
  ret = []
  for i in range(0, len(REGS)):
    if i*4 in regs.daddr:
      ret.append({"name": REGS[i], "address": i*4, "value": regs.daddr[i*4].fetch(clnum)})
  emit('registers', ret)

def start_socketio():
  print "starting socketio server..."
  socketio.run(app, port=3002)

def main():
  print "starting QIRA middleware"

  init()
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
      process(read_log(LOGFILE, changes_committed, max_changes - changes_committed))
      print "done %d to %d" % (changes_committed,max_changes)
      changes_committed = max_changes

if __name__ == '__main__':
  init()
  process(read_log(LOGFILE))
  start_socketio()

  """
  try:
    main()
  finally:
    kill_meteor()
  """

