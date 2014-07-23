import os
import socket
import signal
import fcntl

def get_next_run_id():
  ret = -1
  for i in os.listdir("/tmp/qira_logs/"):
    if "_" in i:
      continue
    ret = max(ret, int(i))
  return ret+1

def init_bindserver():
  global ss, ss2
  # wait for a connection
  ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  ss.bind(("127.0.0.1", 4000))
  ss.listen(5)
  
  ss2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ss2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  ss2.bind(("127.0.0.1", 4001))
  ss2.listen(5)

def start_bindserver(program, myss, parent_id, start_cl, loop = False):
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
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL, 0) & ~os.O_NONBLOCK)
    os.dup2(fd, 0) 
    os.dup2(fd, 1) 
    os.dup2(fd, 2) 
    for i in range(3, fd+1):
      try:
        os.close(i)
      except:
        pass
    # fingerprint here
    os.execvp(program.qirabinary, [program.qirabinary, "-D", "/dev/null", "-d", "in_asm",
      "-qirachild", "%d %d %d" % (parent_id, start_cl, run_id), "-singlestep",
      program.program]+program.args)

