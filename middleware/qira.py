#!/usr/bin/env python

import os
import argparse
import socket
import threading
import time

import qiradb

import qira_socat
import qira_program
import qira_webserver

def run_middleware(program):
  while 1:
    time.sleep(0.2)
    # poll for new traces
    for i in os.listdir("/tmp/qira_logs/"):
      if "_" in i:
        continue
      i = int(i)

      if i not in program.traces:
        nt = qiradb.Trace("/tmp/qira_logs/"+str(i), i, program.tregs[1], len(program.tregs[0]))
        program.traces[i] = nt

    did_update = False
    # poll for updates on existing
    for tn in program.traces:
      if program.traces[tn].did_update():
        did_update = True
    if did_update:
      program.read_asm_file()
      qira_webserver.push_updates()

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description = 'Analyze binary.')
  parser.add_argument('-s', "--server", help="bind on port 4000. like socat", action="store_true")
  parser.add_argument('binary', help="path to the binary")
  parser.add_argument('args', nargs='*', help="arguments to the binary")
  args = parser.parse_args()

  # creates the file symlink, program is constant through server run
  program = qira_program.Program(args.binary, args.args)

  is_qira_running = 1
  try:
    socket.create_connection(('127.0.0.1', QIRA_PORT))
    if args.server:
      raise Exception("can't run as server if QIRA is already running")
  except:
    is_qira_running = 0
    print "no qira server found, starting it"
    program.clear()

  # start the binary runner
  if args.server:
    qira_socat.init_bindserver()
    qira_socat.start_bindserver(ss, -1, 1, True)
  else:
    print "**** running "+program.program
    if is_qira_running or os.fork() == 0:   # cute?
      os.execvp(program.qirabinary, [program.qirabinary, "-D", "/dev/null", "-d", "in_asm",
        "-singlestep",  program.program]+program.args)

  if not is_qira_running:
    # start the http server
    http = threading.Thread(target=qira_webserver.run_socketio, args=[program])
    http.start()

    # this reads the files. replace it with c
    run_middleware(program)

