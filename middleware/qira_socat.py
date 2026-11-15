import os
import socket
import threading
from . import qira_config

def get_next_run_id():
  ret = -1
  for i in os.listdir(qira_config.TRACE_FILE_BASE):
    if "_" in i:
      continue
    ret = max(ret, int(i))
  return ret+1

bound_ports = {}

def start_bindserver(program, port, parent_id, start_cl, loop = False):
  """Listen on port; each client gets a tracer run with the connection as its
  stdin/stdout/stderr (like socat). loop=False serves one client."""
  if port not in bound_ports:
    myss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    myss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    myss.bind((qira_config.HOST, port))
    myss.listen(5)
    bound_ports[port] = myss
  else:
    myss = bound_ports[port]

  # a thread instead of os.fork(): the web server runs threads in this process
  t = threading.Thread(target=_serve, args=(myss, program, parent_id, start_cl, loop), daemon=True)
  t.start()
  return t

def _serve(myss, program, parent_id, start_cl, loop):
  print("**** socat listening on %s:%s" % myss.getsockname())
  while 1:
    try:
      (cs, address) = myss.accept()
    except OSError:
      return  # the listening socket was closed
    run_id = get_next_run_id()
    print("**** ID %s CLIENT %s:%s fd: %s" % (run_id, address[0], address[1], cs.fileno()))
    # python nonblocking is a lie...
    cs.setblocking(True)
    # fingerprint here
    try:
      # Popen restores SIGPIPE to the default in the child, as the legacy fork did
      program.execqira(["-qirachild", "%d %d %d" % (parent_id, start_cl, run_id)], stdio=cs.fileno())
    except Exception as e:
      print("**** socat: %s" % e)
    finally:
      cs.close()  # the tracer has its own copy
    if not loop:
      return
