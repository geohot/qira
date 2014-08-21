import os
import socket
import signal
import qira_config

def get_next_run_id():
  ret = -1
  for i in os.listdir(qira_config.TRACE_FILE_BASE):
    if "_" in i:
      continue
    ret = max(ret, int(i))
  return ret+1

bound_ports = {}

def start_bindserver(program, port, parent_id, start_cl, loop = False):
  if port not in bound_ports:
    myss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    myss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    myss.bind(("127.0.0.1", port))
    myss.listen(5)
    bound_ports[port] = myss
  else:
    myss = bound_ports[port]
    
  if os.fork() != 0:
    return
  # bindserver runs in a fork
  while 1:
    print "**** listening on",myss
    (cs, address) = myss.accept()

    # fork off the child if we are looping
    if loop:
      if os.fork() != 0:
        cs.close()
        continue
    run_id = get_next_run_id()
    print "**** ID",run_id,"CLIENT",cs, address, cs.fileno()

    fd = cs.fileno()
    # python nonblocking is a lie...
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
      import fcntl
      fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL, 0) & ~os.O_NONBLOCK)
    except:
      pass
    os.dup2(fd, 0) 
    os.dup2(fd, 1) 
    os.dup2(fd, 2) 
    for i in range(3, fd+1):
      try:
        os.close(i)
      except:
        pass
    # fingerprint here
    program.execqira(["-qirachild", "%d %d %d" % (parent_id, start_cl, run_id)], shouldfork=False)

