import os
import sys
import argparse
import ipaddress
import socket

from . import qira_config
from . import qira_socat
from . import qira_program
from . import qira_webserver

def qira_is_running(host, port):
  """True if something accepts connections on the web port (another QIRA)."""
  # a wildcard listen address is reached through loopback
  ip = ipaddress.ip_address(host)
  if ip.is_unspecified:
    host = "127.0.0.1" if ip.version == 4 else "::1"
  try:
    socket.create_connection((host, port), timeout=1).close()
    return True
  except OSError:
    return False

def main():
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
  parser.add_argument('-S', '--static', help="enable static2", action="store_true")
  parser.add_argument('--no-run', help="don't run the program", action="store_true")
  parser.add_argument('--no-delete-runs', help="don't clear the logs", action="store_true")
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
  if args.socat_port < 1 or args.socat_port > 65534:
    raise Exception("--socat-port must be a valid port number (1-65534)")
  try:
    args.host = ipaddress.ip_address(args.host).exploded
  except ValueError:
    raise Exception("--web-host must be a valid IPv4/IPv6 address")

  # handle arguments
  if sys.platform == "darwin":
    print("*** running on darwin, defaulting to --pin")
    qira_config.USE_PIN = True
  else:
    qira_config.USE_PIN = args.pin


  qira_config.HOST = args.host
  qira_config.WEB_PORT = args.web_port
  qira_config.SOCAT_PORT = args.socat_port
  qira_config.FORK_PORT = args.socat_port + 1

  if args.tracelibraries:
    qira_config.TRACE_LIBRARIES = True

  if args.static:
    print("*** using static")
    qira_config.WITH_STATIC = True
  if args.flush_cache:
    print("*** flushing caches")
    qira_program.flush_caches()

  # qemu args from command line
  qemu_args = []
  if args.gate_trace != None:
    qemu_args.append("-gatetrace")
    qemu_args.append(args.gate_trace)

  # program is constant through server run
  program = qira_program.Program(args.binary, args.args, qemu_args)

  is_qira_running = qira_is_running(qira_config.HOST, qira_config.WEB_PORT)
  if is_qira_running:
    if args.server:
      sys.exit("can't run as server if QIRA is already running (port %d is in use)" % qira_config.WEB_PORT)
  else:
    print("no qira server found, starting it")
    program.clear(not args.no_delete_runs)

  # start the binary runner
  if args.server:
    qira_socat.start_bindserver(program, qira_config.SOCAT_PORT, -1, 1, True)
  else:
    if not args.no_run:
      print("**** running",program.program)
      try:
        program.execqira(shouldfork=not is_qira_running)
      except qira_program.TracerNotFound as e:
        sys.exit("\n%s" % e)

  if not is_qira_running:
    # start the http server
    qira_webserver.run_server(args, program)

if __name__ == '__main__':
  main()

