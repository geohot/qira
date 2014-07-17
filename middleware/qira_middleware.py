#!/usr/bin/env python
import qira_log
import qira_trace
import socket
import threading
import time
import sys
import os
import fcntl

from flask import Flask, Response
from flask.ext.socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

program = None
trace = None
traces = {}
run_id = 0

# ***** after this line is the new server stuff *****

@socketio.on('forkat', namespace='/qira')
def forkat(forknum, clnum):
  global run_id
  print "forkat",forknum,clnum
  start_bindserver(ss2, forknum, clnum)

@socketio.on('connect', namespace='/qira')
def connect():
  print "client connected", program.get_maxclnum()
  emit('maxclnum', program.get_maxclnum())
  emit('pmaps', program.pmaps)

@socketio.on('getclnum', namespace='/qira')
def getclnum(forknum, clnum, types, limit):
  if forknum not in traces:
    return
  if clnum == None or types == None or limit == None:
    return
  ret = []
  for t in types:
    key = (clnum, t)
    for c in traces[forknum].pydb_clnum[key]:
      ret.append(c)
      if len(ret) >= limit:
        break
    if len(ret) >= limit:
      break
  emit('clnum', ret)

@socketio.on('getchanges', namespace='/qira')
def getchanges(forknum, address, typ):
  if forknum not in traces:
    return
  if address == None or typ == None:
    return
  emit('changes', {'forknum': forknum, 'type': typ, 'clnums': traces[forknum].pydb_addr[(address, typ)]})

@socketio.on('getinstructions', namespace='/qira')
def getinstructions(forknum, clstart, clend):
  if forknum not in traces:
    return
  if clstart == None or clend == None:
    return
  ret = []
  pydb_clnum = traces[forknum].pydb_clnum 
  for i in range(clstart, clend):
    key = (i, 'I')
    if key in pydb_clnum:
      ret.append(pydb_clnum[key][0])
  emit('instructions', ret)

@socketio.on('getmemory', namespace='/qira')
def getmemory(forknum, clnum, address, ln):
  if forknum not in traces:
    return
  if clnum == None or address == None or ln == None:
    return
  dat = traces[forknum].mem.fetch(clnum, address, ln)
  ret = {'address': address, 'len': ln, 'dat': dat}
  emit('memory', ret)

@socketio.on('getregisters', namespace='/qira')
def getregisters(forknum, clnum):
  if forknum not in traces:
    return
  #print "getregisters",clnum
  if clnum == None:
    return
  # register names shouldn't be here
  # though i'm not really sure where a better place is, qemu has this information
  ret = []
  REGS = program.tregs[0]
  REGSIZE = program.tregs[1]
  for i in range(0, len(REGS)):
    if i*REGSIZE in traces[forknum].regs.daddr:
      rret = {"name": REGS[i], "address": i*REGSIZE, "value": traces[forknum].regs.daddr[i*REGSIZE].fetch(clnum), "size": REGSIZE, "regactions": ""}
      if clnum in traces[forknum].pydb_addr[(i*REGSIZE, 'R')]:
        rret['regactions'] += " regread"
      if clnum in traces[forknum].pydb_addr[(i*REGSIZE, 'W')]:
        rret['regactions'] += " regwrite"
      ret.append(rret)
  emit('registers', ret)

@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
def serve(path):
  # best security?
  if ".." in path:
    return
  webstatic = os.path.dirname(os.path.realpath(__file__))+"/../webstatic/"

  ext = path.split(".")[-1]

  if ext == 'css':
    path = "qira.css"

  dat = open(webstatic+path).read()
  if ext == 'js' and not path.startswith('client/compatibility/') and not path.startswith('packages/'):
    dat = "(function(){"+dat+"})();"

  if ext == 'js':
    return Response(dat, mimetype="application/javascript")
  elif ext == 'css':
    return Response(dat, mimetype="text/css")
  else:
    return Response(dat, mimetype="text/html")

def run_socketio():
  print "starting socketio server..."
  socketio.run(app, port=3002)

def check_file(logfile, trace):
  global program
  max_changes = qira_log.get_log_length(logfile)
  if max_changes == None:
    return False
  if max_changes < trace.changes_committed:
    print "RESTART..."+logfile
    trace.reset()
  if trace.changes_committed < max_changes:
    sys.stdout.write("on %s going from %d to %d..." % (logfile, trace.changes_committed,max_changes))
    sys.stdout.flush()
    log = qira_log.read_log(logfile, trace.changes_committed, max_changes - trace.changes_committed)
    sys.stdout.write("read..."); sys.stdout.flush()
    trace.process(log)
    print "done", trace.maxclnum
    trace.changes_committed = max_changes
    return True
  return False

def run_middleware():
  global program, traces
  print "starting QIRA middleware"

  # run loop run
  # read in all the traces
  while 1:
    time.sleep(0.05)
    did_update = False
    for i in os.listdir("/tmp/qira_logs/"):
      i = int(i)
      if i not in traces:
        traces[i] = qira_trace.Trace(program, i)
      if check_file("/tmp/qira_logs/"+str(i), traces[i]):
        did_update = True

    if did_update:
      # push to all connected websockets
      socketio.emit('pmaps', program.pmaps, namespace='/qira')

      # this must happen last
      socketio.emit('maxclnum', program.get_maxclnum(), namespace='/qira')
      

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

def start_bindserver(myss, parent_id, start_cl, loop = False):
  if loop:
    if os.fork() != 0:
      return
  while 1:
    # bindserver runs in a fork
    if os.fork() == 0:
      print "**** listening on",myss
      (cs, address) = myss.accept()
      run_id = get_next_run_id()
      print "**** ID",run_id,"CLIENT",cs, address, cs.fileno()

      fd = cs.fileno()
      # python nonblocking is a lie...
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
      os.execvp('qira-i386', ["qira-i386", "-qirachild",
        "%d %d %d" % (parent_id, start_cl, run_id), "-singlestep",
        "/tmp/qira_binary"]+sys.argv[2:])
    if not loop:
      break
    print os.wait()
    print "**** CLIENT DONE"

def delete_old_runs():
  # delete the logs
  try:
    os.mkdir("/tmp/qira_logs")
  except:
    pass
  for i in os.listdir("/tmp/qira_logs"):
    os.unlink("/tmp/qira_logs/"+i)

def get_next_run_id():
  ret = -1
  for i in os.listdir("/tmp/qira_logs/"):
    ret = max(ret, int(i))
  return ret+1

if __name__ == '__main__':
  if len(sys.argv) < 2:
    print "usage: %s <target binary>" % sys.argv[0]
    exit(-1)
  #delete_old_runs()

  # creates the file symlink, program is constant through server run
  program = qira_trace.Program(os.path.realpath(sys.argv[1]))

  # start the first binary running
  # i guess most things after this will be forks
  init_bindserver()
  start_bindserver(ss, -1, 1, True)

  # start the http server
  http = threading.Thread(target=run_socketio)
  http.start()

  run_middleware()

