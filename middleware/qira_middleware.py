#!/usr/bin/env python
import qira_log
import qira_trace
import socket
import threading
import time
import sys
import os
import fcntl
import signal
import argparse


program = None
run_id = 0


@socketio.on('getclnum', namespace='/qira')
def getclnum(forknum, clnum, types, limit):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  if clnum == None or types == None or limit == None:
    return
  ret = []
  for t in types:
    key = (clnum, t)
    for c in trace.pydb_clnum[key]:
      c = c.copy()
      c['address'] = ghex(c['address'])
      c['data'] = ghex(c['data'])
      ret.append(c)
      if len(ret) >= limit:
        break
    if len(ret) >= limit:
      break
  emit('clnum', ret)

@socketio.on('getchanges', namespace='/qira')
def getchanges(forknum, address, typ):
  if address == None or typ == None:
    return
  if forknum != -1 and forknum not in program.traces:
    return
  address = int(address)
  if forknum == -1:
    ret = {}
    for forknum in program.traces:
      ret[forknum] = program.traces[forknum].pydb_addr[(address, typ)]
    emit('changes', {'type': typ, 'clnums': ret})
  else:
    emit('changes', {'type': typ, 'clnums': {forknum: program.traces[forknum].pydb_addr[(address, typ)]}})

@socketio.on('getinstructions', namespace='/qira')
def getinstructions(forknum, clstart, clend):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  if clstart == None or clend == None:
    return
  ret = []
  pydb_clnum = trace.pydb_clnum 
  for i in range(clstart, clend):
    key = (i, 'I')
    if key in pydb_clnum:
      rret = pydb_clnum[key][0]
      if rret['address'] in program.instructions:
        rret['instruction'] = program.instructions[rret['address']]
      ret.append(rret)
  emit('instructions', ret)

@socketio.on('getmemory', namespace='/qira')
def getmemory(forknum, clnum, address, ln):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  if clnum == None or address == None or ln == None:
    return
  address = int(address)
  dat = trace.mem.fetch(clnum, address, ln)
  ret = {'address': address, 'len': ln, 'dat': dat}
  emit('memory', ret)

@socketio.on('getregisters', namespace='/qira')
def getregisters(forknum, clnum):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  #print "getregisters",clnum
  if clnum == None:
    return
  # register names shouldn't be here
  # though i'm not really sure where a better place is, qemu has this information
  ret = []
  REGS = program.tregs[0]
  REGSIZE = program.tregs[1]
  for i in range(0, len(REGS)):
    if i*REGSIZE in trace.regs.daddr:
      rret = {"name": REGS[i], "address": i*REGSIZE, "value": ghex(trace.regs.daddr[i*REGSIZE].fetch(clnum)), "size": REGSIZE, "regactions": ""}
      # this +1 is an ugly hack
      if (clnum+1) in trace.pydb_addr[(i*REGSIZE, 'R')]:
        rret['regactions'] = "regread"
      if (clnum+1) in trace.pydb_addr[(i*REGSIZE, 'W')]:
        if "regread" == rret['regactions']:
          rret['regactions'] = "regreadwrite"
        else:
          rret['regactions'] = "regwrite"
      ret.append(rret)
  emit('registers', ret)



def run_middleware():
  global program
  print "starting QIRA middleware"

  # run loop run
  # read in all the traces
  while 1:
    time.sleep(0.2)
    did_update = False
    for i in os.listdir("/tmp/qira_logs/"):
      if "_" in i:
        continue
      i = int(i)
      if i not in program.traces:
        #print "C create trace",qiradb.new_trace("/tmp/qira_logs/"+str(i), i, program.tregs[1], len(program.tregs[0]))
        qira_trace.Trace(program, i)

    for tn in program.traces:
      if program.traces[tn].poll():
        did_update = True

    if did_update:
      # push to all connected websockets
      socketio.emit('pmaps', program.pmaps, namespace='/qira')

      # this must happen last
      socketio.emit('maxclnum', program.get_maxclnum(), namespace='/qira')
      

