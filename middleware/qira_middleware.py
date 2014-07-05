#!/usr/bin/env python
from qira_log import *
from qira_memory import *
import subprocess
import time
import sys
import os
import json
import signal
import socket
from pymongo import MongoClient

# global state for the program
instructions = {}
pmaps = {}
regs = Memory()
mem = Memory()

meteor_pid = -1

def mongo_connect():
  while 1:
    try:
      db = MongoClient('localhost', 3001).meteor
      db.bob.insert([{"test":"test"}])
      db.bob.drop()  # poor bob, be master
      break
    except:
      try:
        db.connection.close()
      except:
        pass
      time.sleep(0.1)
  return db

def process(log_entries):
  global instructions, pmaps, regs, mem
  db = mongo_connect()
  Change = db.change
  Pmaps = db.pmaps

  db_changes = []
  new_pmaps = pmaps.copy()

  for (address, data, clnum, flags) in log_entries:
    # Changes database
    this_change = {'address': address, 'type': flag_to_type(flags),
        'size': flags&SIZE_MASK, 'clnum': clnum, 'data': data}
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

  # we shouldn't be rewriting this every time
  open("/tmp/qira_memdb", "wb").write(
    json.dumps({"regs": regs.dump(), "mem": mem.dump()}))

  # push new pmaps
  db_pmaps = []
  for i in new_pmaps:
    if i not in pmaps or pmaps[i] != new_pmaps[i]:
      db_pmaps.append({"address": i, "type": new_pmaps[i]})

  if len(db_pmaps) > 0:
    Pmaps.insert(db_pmaps)
  pmaps = new_pmaps

  # push changes to db
  if len(db_changes) > 0:
    Change.insert(db_changes)
  db.connection.close()


def init():
  global instructions, pmaps, regs, mem
  global meteor_pid
  instructions = {}
  pmaps = {}
  regs = Memory()
  mem = Memory()
  print "reset program state"

  # get the memory base
  # TODO: read the elf file sections

  # get the instructions
  objdump_out = subprocess.Popen(
    ["objdump", "-d", "/tmp/qira_binary"],
    stdout = subprocess.PIPE).communicate()[0]
  for line in objdump_out.split("\n"):
    line = line.split("\t")
    if len(line) == 3:
      addr = int(line[0].strip(" :"), 16)
      instructions[addr] = line[2]
      #print hex(addr), line[2]
    else:
      # could get names here too, but maybe useless for now
      pass
  print "objdump parse got",len(instructions),"instructions"

  open("/tmp/qira_memdb", "wb").write(
    json.dumps({"regs": regs.dump(), "mem": mem.dump()}))
  print "wrote initial qira_memdb"

  # connect to db, set up collections, and drop
  print "restarting meteor"
  kill_meteor()
  start_meteor()
  print "waiting for mongo connection"
  db = mongo_connect()
  Change = db.change
  Pmaps = db.pmaps
  Change.drop()
  Pmaps.drop()
  db.connection.close()
  print "dropped old databases"

def wait_for_port(port, closed=False):
  while 1:
    try:
      s = socket.create_connection(("localhost", port))
      s.close()
      if closed == False:
        return
    except socket.error:
      if closed == True:
        return
    time.sleep(0.1)

def start_meteor():
  global meteor_pid
  ret = os.fork()
  if ret == 0:
    os.chdir(os.path.dirname(os.path.realpath(__file__))+"/../web/")
    os.environ['PATH'] += ":"+os.getenv("HOME")+"/.meteor/tools/latest/bin/"
    os.execvp("mrt", ["mrt"])
  meteor_pid = ret
  print "waiting for mongodb startup"
  wait_for_port(3000)
  wait_for_port(3001)
  print "socket ports are open"
  time.sleep(5)
  print "meteor started with pid",meteor_pid

def kill_meteor():
  global meteor_pid
  if meteor_pid != -1:
    print "killing meteor"
    sys.stdout.flush()
    os.kill(meteor_pid, signal.SIGINT)
    print os.waitpid(meteor_pid, 0)
    print "meteor is dead"
    meteor_pid = -1
  print "waiting for ports to be closed"
  wait_for_port(3000, True)
  os.system("killall mongod")   # OMG WHY DO I NEED THIS?
  wait_for_port(3001, True)
  print "ports are closed"

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
  try:
    main()
  finally:
    kill_meteor()

