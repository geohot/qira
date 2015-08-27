#!/usr/bin/env python2.7
import os
import sys
basedir = os.path.dirname(os.path.realpath(__file__))
import argparse
import ipaddr
import socket
import threading
import time

import qira_config
import qira_socat
import qira_program
import qira_webserver

if __name__ == '__main__':
  # define arguments
  parser = argparse.ArgumentParser(description = 'Analyze binary. Like "qira /bin/ls /"')
  parser.add_argument('-s', "--server", help="bind on port 4000. like socat", action="store_true")
  parser.add_argument('-t', "--tracelibraries", help="trace into all libraries", action="store_true")
  parser.add_argument('binary', help="path to the binary")
  parser.add_argument('args', nargs='*', help="arguments to the binary")
  parser.add_argument("--gate-trace", metavar="ADDRESS", help="don't start tracing until this address is hit")
  parser.add_argument("--flush-cache", help="flush all QIRA caches", action="store_true")
  parser.add_argument("--pin", help="use pin as the backend, requires ./pin_build.sh", action="store_true")
  parser.add_argument("--host", metavar="HOST", help="listen address for web interface and socat. "+qira_config.HOST+" by default", default=qira_config.HOST)
  parser.add_argument("--web-port", metavar="PORT", help="listen port for web interface. 3002 by default", type=int, default=qira_config.WEB_PORT)
  parser.add_argument("--socat-port", metavar="PORT", help="listen port for socat. 4000 by default", type=int, default=qira_config.SOCAT_PORT)
  parser.add_argument('-S', help="enable static2", action="store_true")
  parser.add_argument("--static-engine", metavar="STATIC_ENGINE", help="static engine to use with static2 (builtin or r2)", nargs="?")
  #capstone flag in qira_config for now

  # parse arguments, first try
  args, unknown = parser.parse_known_args()

  # hack to allow arguments to be passed to the analyzed program
  sys.argv.insert(sys.argv.index(args.binary), "--")

  # parse args, second try
  args = parser.parse_args()

  # validate arguments
  if args.web_port < 1 or args.web_port > 65535:
    raise Exception("--web-port must be a valid port number (1-65535)")
  if args.socat_port < 1 or args.socat_port > 65535:
    raise Exception("--socat-port must be a valid port number (1-65535)")
  try:
    args.host = ipaddr.IPAddress(args.host).exploded
  except ValueError:
    raise Exception("--web-host must be a valid IPv4/IPv6 address")

  # handle arguments
  if sys.platform == "darwin":
    print "*** running on darwin, defaulting to --pin"
    qira_config.USE_PIN = True
  else:
    qira_config.USE_PIN = args.pin


  qira_config.HOST = args.host
  qira_config.WEB_PORT = args.web_port
  qira_config.SOCAT_PORT = args.socat_port
  qira_config.FORK_PORT = args.socat_port + 1

  if args.tracelibraries:
    qira_config.TRACE_LIBRARIES = True

  if args.S:
    print "*** using static"
    qira_config.WITH_STATIC = True
  if args.static_engine:
    print "*** using static engine", args.static_engine
    qira_config.WITH_STATIC = True
    qira_config.STATIC_ENGINE = args.static_engine
  if args.flush_cache:
    print "*** flushing caches"
    os.system("rm -rfv /tmp/qira*")

  # qemu args from command line
  qemu_args = []
  if args.gate_trace != None:
    qemu_args.append("-gatetrace")
    qemu_args.append(args.gate_trace)

  # creates the file symlink, program is constant through server run
  program = qira_program.Program(args.binary, args.args, qemu_args)

  is_qira_running = 1
  try:
    socket.create_connection(('127.0.0.1', qira_config.WEB_PORT))
    if args.server:
      raise Exception("can't run as server if QIRA is already running")
  except:
    is_qira_running = 0
    print "no qira server found, starting it"
    program.clear()

  # start the binary runner
  if args.server:
    qira_socat.start_bindserver(program, qira_config.SOCAT_PORT, -1, 1, True)
  else:
    print "**** running "+program.program
    program.execqira(shouldfork=not is_qira_running)

  if not is_qira_running:
    # start the http server
    qira_webserver.run_server(args, program)

