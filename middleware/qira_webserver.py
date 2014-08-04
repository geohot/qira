from qira_base import *
import qira_config
import os
import sys
basedir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(basedir+"/../cda")

def debug():
  return
  import inspect
  curframe = inspect.currentframe()
  calframe = inspect.getouterframes(curframe, 2)
  print calframe[1][3],"called"
  #print inspect.getargvalues(calframe)
  #print args, values
  

import qira_socat
import time

import qira_analysis
import qira_log

LIMIT = 400

from flask import Flask, Response
from flask.ext.socketio import SocketIO, emit

# http://stackoverflow.com/questions/8774958/keyerror-in-module-threading-after-a-successful-py-test-run
import threading
import sys
if 'threading' in sys.modules:
  del sys.modules['threading']
import gevent
import gevent.socket
import gevent.monkey
gevent.monkey.patch_all()
# done with that

app = Flask(__name__)
#app.config['DEBUG'] = True
socketio = SocketIO(app)

# ***** middleware moved here *****
def push_updates():
  socketio.emit('pmaps', program.get_pmaps(), namespace='/qira')
  socketio.emit('maxclnum', program.get_maxclnum(), namespace='/qira')

def mwpoll():
  # poll for new traces, call this every once in a while
  for i in os.listdir("/tmp/qira_logs/"):
    if "_" in i:
      continue
    i = int(i)

    if i not in program.traces:
      program.add_trace("/tmp/qira_logs/"+str(i), i)

  did_update = False
  # poll for updates on existing
  for tn in program.traces:
    if program.traces[tn].db.did_update():
      did_update = True
  if did_update:
    program.read_asm_file()
    push_updates()

def mwpoller():
  while 1:
    time.sleep(0.2)
    mwpoll()

# ***** after this line is the new server stuff *****

@socketio.on('navigateline', namespace='/cda')
def navigateline(fn, ln):
  #print 'navigateline',fn,ln
  try:
    iaddr = program.rdwarves[fn+"#"+str(ln)]
  except:
    return
  #print 'navigateline',fn,ln,iaddr
  socketio.emit('setiaddr', iaddr, namespace='/qira')

@socketio.on('navigateiaddr', namespace='/qira')
def navigateiaddr(iaddr):
  if iaddr == None:
    return
  try:
    (filename, line, linedat) = program.dwarves[iaddr]
  except:
    return
  #print 'navigateiaddr', hex(iaddr), filename, line
  socketio.emit('setline', filename, line, namespace='/cda')

@socketio.on('forkat', namespace='/qira')
def forkat(forknum, clnum, pending):
  global program
  print "forkat",forknum,clnum,pending

  REGSIZE = program.tregs[1]
  dat = []
  for p in pending:
    daddr = fhex(p['daddr'])
    ddata = fhex(p['ddata'])
    if len(p['ddata']) > 4:
      # ugly hack
      dsize = REGSIZE
    else:
      dsize = 1
    flags = qira_log.IS_VALID | qira_log.IS_WRITE
    if daddr >= 0x1000:
      flags |= qira_log.IS_MEM
    flags |= dsize*8
    dat.append((daddr, ddata, clnum-1, flags))

  next_run_id = qira_socat.get_next_run_id()

  if len(dat) > 0:
    qira_log.write_log("/tmp/qira_logs/"+str(next_run_id)+"_mods", dat)

  if args.server:
    qira_socat.start_bindserver(program, qira_config.FORK_PORT, forknum, clnum)
  else:
    if os.fork() == 0:
      program.execqira(["-qirachild", "%d %d %d" % (forknum, clnum, next_run_id)])


@socketio.on('deletefork', namespace='/qira')
def deletefork(forknum):
  global program
  print "deletefork", forknum
  try:
    os.unlink("/tmp/qira_logs/"+str(int(forknum)))
    del program.traces[forknum]
  except:
    pass
  push_updates()

@socketio.on('doslice', namespace='/qira')
def slice(forknum, clnum):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  debug()
  data = qira_analysis.slice(trace, clnum)
  print "slice",forknum,clnum, data
  emit('slice', forknum, data);

@socketio.on('doanalysis', namespace='/qira')
def analysis(forknum):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  debug()
  # this fails sometimes, who knows why
  try:
    data = qira_analysis.analyze(trace, program)
  except Exception as e:
    print "!!! analysis failed on",forknum,"because",e
    data = None
  if data != None:
    emit('setpicture', {"forknum":forknum, "data":data})
  
@socketio.on('connect', namespace='/qira')
def connect():
  global program
  print "client connected", program.get_maxclnum()
  emit('pmaps', program.get_pmaps())
  emit('maxclnum', program.get_maxclnum())

@socketio.on('getclnum', namespace='/qira')
def getclnum(forknum, clnum, types, limit):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  if clnum == None or types == None or limit == None:
    return
  debug()
  ret = []
  for c in trace.db.fetch_changes_by_clnum(clnum, LIMIT):
    if c['type'] not in types:
      continue
    c = c.copy()
    c['address'] = ghex(c['address'])
    c['data'] = ghex(c['data'])
    ret.append(c)
    if len(ret) >= limit:
      break
  emit('clnum', ret)

@socketio.on('getchanges', namespace='/qira')
def getchanges(forknum, address, typ):
  if address == None or typ == None:
    return
  if forknum != -1 and forknum not in program.traces:
    return
  debug()
  address = fhex(address)

  if forknum == -1:
    forknums = program.traces.keys()
  else:
    forknums = [forknum]
  ret = {}
  for forknum in forknums:
    ret[forknum] = program.traces[forknum].db.fetch_clnums_by_address_and_type(address, chr(ord(typ[0])), 0, LIMIT)
  emit('changes', {'type': typ, 'clnums': ret})

@socketio.on('getinstructions', namespace='/qira')
def getinstructions(forknum, clnum, clstart, clend):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  if clstart == None or clend == None:
    return
  debug()
  slce = qira_analysis.slice(trace, clnum)
  ret = []
  for i in range(clstart, clend):
    rret = trace.db.fetch_changes_by_clnum(i, 1)
    if len(rret) == 0:
      continue
    else:
      rret = rret[0]
    if rret['address'] in program.instructions:
      rret['instruction'] = program.instructions[rret['address']]
    if rret['address'] in program.dwarves:
      rret['comment'] = program.dwarves[rret['address']][2]
    if i in slce:
      rret['slice'] = True
    else:
      rret['slice'] = False
    # for numberless javascript
    rret['address'] = ghex(rret['address'])
    ret.append(rret)
  emit('instructions', ret)

@socketio.on('getmemory', namespace='/qira')
def getmemory(forknum, clnum, address, ln):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  if clnum == None or address == None or ln == None:
    return
  debug()
  address = fhex(address)
  dat = trace.fetch_memory(clnum, address, ln)
  ret = {'address': address, 'len': ln, 'dat': dat, 'is_big_endian': program.tregs[2], 'ptrsize': program.tregs[1]}
  emit('memory', ret)

@socketio.on('getregisters', namespace='/qira')
def getregisters(forknum, clnum):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  if clnum == None:
    return
  debug()
  # register names shouldn't be here
  # though i'm not really sure where a better place is, qemu has this information
  ret = []
  REGS = program.tregs[0]
  REGSIZE = program.tregs[1]

  cls = trace.db.fetch_changes_by_clnum(clnum+1, LIMIT)
  regs = trace.db.fetch_registers(clnum)

  for i in range(0, len(REGS)):
    rret = {"name": REGS[i], "address": i*REGSIZE, "value": ghex(regs[i]), "size": REGSIZE, "regactions": ""}
      
    act = set()
    for c in cls:
      if c['address'] == i*REGSIZE:
        act.add(c['type'])

    # this +1 is an ugly hack
    if 'R' in act:
      rret['regactions'] = "regread"

    if 'W' in act:
      if "regread" == rret['regactions']:
        rret['regactions'] = "regreadwrite"
      else:
        rret['regactions'] = "regwrite"
    ret.append(rret)

  emit('registers', ret)

@socketio.on('getstrace', namespace='/qira')
def get_strace(forknum):
  if forknum not in program.traces:
    return
  trace = program.traces[forknum]
  debug()
  try:
    f = open("/tmp/qira_logs/"+str(int(forknum))+"_strace").read()
  except:
    return "no strace"

  ret = []
  for ff in f.split("\n"):
    if ff == '':
      continue
    ff = ff.split(" ")
    try:
      clnum = int(ff[0])
    except:
      continue
    if clnum == trace.db.get_minclnum():
      # filter the boring syscalls
      continue
    pid = int(ff[1])
    sc = " ".join(ff[2:])
    ret.append({"clnum": clnum, "pid":pid, "sc": sc})
  # LIMIT for web interface
  emit('strace', ret[0:LIMIT])


# ***** generic webserver stuff *****
  
@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
def serve(path):
  # best security?
  if ".." in path:
    return
  webstatic = os.path.dirname(os.path.realpath(__file__))+"/../webstatic/"

  ext = path.split(".")[-1]

  try:
    dat = open(webstatic+path).read()
  except:
    return ""
  if ext == 'js' and not path.startswith('client/compatibility/') and path.startswith('client/'):
    dat = "(function(){"+dat+"})();"

  if ext == 'js':
    return Response(dat, mimetype="application/javascript")
  elif ext == 'css':
    return Response(dat, mimetype="text/css")
  else:
    return Response(dat, mimetype="text/html")

def run_server(largs, lprogram):
  global args
  global program
  args = largs
  program = lprogram
  if qira_config.WITH_CDA:
    import cacheserver
    app.register_blueprint(cacheserver.app)
    cacheserver.set_cache(program.cda)
  print "starting socketio server..."
  threading.Thread(target=mwpoller).start()
  socketio.run(app, host=qira_config.WEB_HOST, port=qira_config.WEB_PORT)

