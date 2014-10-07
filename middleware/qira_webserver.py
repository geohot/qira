from qira_base import *
import qira_config
import os
import sys
import time
import base64
import json
sys.path.append(qira_config.BASEDIR+"/cda")

def socket_method(func):
  def func_wrapper(*args, **kwargs):
    # before things are initted in the js, we get this
    for i in args:
      if i == None:
        #print "BAD ARGS TO %-20s" % (func.func_name), "with",args
        return
    try:
      start = time.time()
      ret = func(*args, **kwargs)
      tm = (time.time() - start) * 1000

      # print slow calls, slower than 50ms
      if tm > 50 or qira_config.WEBSOCKET_DEBUG:
        print "SOCKET %6.2f ms in %-20s with" % (tm, func.func_name), args
      return ret
    except Exception, e:
      print "ERROR",e,"in",func.func_name,"with",args
  return func_wrapper

import qira_socat
import time

import qira_analysis
import qira_log

LIMIT = 0

from flask import Flask, Response, redirect, request
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
def push_trace_update(i):
  t = program.traces[i]
  if t.picture != None:
    #print t.forknum, t.picture
    socketio.emit('setpicture', {"forknum":t.forknum, "data":t.picture,
      "minclnum":t.minclnum, "maxclnum":t.maxclnum}, namespace='/qira')
  socketio.emit('strace', {'forknum': t.forknum, 'dat': t.strace}, namespace='/qira')
  t.needs_update = False

def push_updates(full = True):
  socketio.emit('pmaps', program.get_pmaps(), namespace='/qira')
  socketio.emit('maxclnum', program.get_maxclnum(), namespace='/qira')
  socketio.emit('arch', program.tregs, namespace='/qira')
  if not full:
    return
  for i in program.traces:
    push_trace_update(i)

def mwpoll():
  # poll for new traces, call this every once in a while
  for i in os.listdir(qira_config.TRACE_FILE_BASE):
    if "_" in i:
      continue
    i = int(i)

    if i not in program.traces:
      program.add_trace(qira_config.TRACE_FILE_BASE+str(i), i)

  did_update = False
  # poll for updates on existing
  for tn in program.traces:
    if program.traces[tn].db.did_update():
      t = program.traces[tn]
      t.read_strace_file()
      socketio.emit('strace', {'forknum': t.forknum, 'dat': t.strace}, namespace='/qira')
      did_update = True

    # trace specific stuff
    if program.traces[tn].needs_update:
      push_trace_update(tn)

  if did_update:
    program.read_asm_file()
    push_updates(False)

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
  socketio.emit('setiaddr', ghex(iaddr), namespace='/qira')

@socketio.on('navigateiaddr', namespace='/qira')
@socket_method
def navigateiaddr(iaddr):
  iaddr = fhex(iaddr)
  if iaddr in program.dwarves:
    (filename, line, linedat) = program.dwarves[iaddr]
    #print 'navigateiaddr', hex(iaddr), filename, line
    socketio.emit('setline', filename, line, namespace='/cda')

@socketio.on('forkat', namespace='/qira')
@socket_method
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
    qira_log.write_log(qira_config.TRACE_FILE_BASE+str(next_run_id)+"_mods", dat)

  if args.server:
    qira_socat.start_bindserver(program, qira_config.FORK_PORT, forknum, clnum)
  else:
    if os.fork() == 0:
      program.execqira(["-qirachild", "%d %d %d" % (forknum, clnum, next_run_id)])


@socketio.on('deletefork', namespace='/qira')
@socket_method
def deletefork(forknum):
  global program
  print "deletefork", forknum
  os.unlink(qira_config.TRACE_FILE_BASE+str(int(forknum)))
  del program.traces[forknum]
  push_updates()

@socketio.on('doslice', namespace='/qira')
@socket_method
def slice(forknum, clnum):
  trace = program.traces[forknum]
  data = qira_analysis.slice(trace, clnum)
  print "slice",forknum,clnum, data
  emit('slice', forknum, data);

@socketio.on('doanalysis', namespace='/qira')
@socket_method
def analysis(forknum):
  trace = program.traces[forknum]

  data = qira_analysis.get_vtimeline_picture(trace)
  if data != None:
    emit('setpicture', {"forknum":forknum, "data":data})
  
@socketio.on('connect', namespace='/qira')
@socket_method
def connect():
  global program
  print "client connected", program.get_maxclnum()
  push_updates()

@socketio.on('getclnum', namespace='/qira')
@socket_method
def getclnum(forknum, clnum, types, limit):
  trace = program.traces[forknum]
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
@socket_method
def getchanges(forknum, address, typ, cview, cscale, clnum):
  if forknum != -1 and forknum not in program.traces:
    return
  address = fhex(address)

  if forknum == -1:
    forknums = program.traces.keys()
  else:
    forknums = [forknum]
  ret = {}
  for forknum in forknums:
    db = program.traces[forknum].db.fetch_clnums_by_address_and_type(address, chr(ord(typ[0])), cview[0], cview[1], LIMIT)
    # send the clnum and the bunch closest on each side
    if len(db) > 50:
      send = set()
      bisect = 0
      last = None
      cnt = 0
      for cl in db:
        if cl <= clnum:
          bisect = cnt
        cnt += 1
        if last != None and (cl - last) < cscale:
          continue
        send.add(cl)
        last = cl
      add = db[max(0,bisect-4):min(len(db), bisect+5)]
      #print bisect, add, clnum
      for tmp in add:
        send.add(tmp)
      ret[forknum] = list(send)
    else:
      ret[forknum] = db
  emit('changes', {'type': typ, 'clnums': ret})

@socketio.on('navigatefunction', namespace='/qira')
@socket_method
def navigatefunction(forknum, clnum, start):
  trace = program.traces[forknum]
  myd = trace.dmap[clnum]
  ret = clnum
  while 1:
    if trace.dmap[clnum] == myd-1:
      break
    ret = clnum
    if start:
      clnum -= 1
    else:
      clnum += 1
    if clnum == trace.minclnum or clnum == trace.maxclnum:
      ret = clnum
      break
  emit('setclnum', forknum, ret)


@socketio.on('getinstructions', namespace='/qira')
@socket_method
def getinstructions(forknum, clnum, clstart, clend):
  trace = program.traces[forknum]
  slce = qira_analysis.slice(trace, clnum)
  ret = []
  for i in range(clstart, clend):
    rret = trace.db.fetch_changes_by_clnum(i, 1)
    if len(rret) == 0:
      continue
    else:
      rret = rret[0]

    rret['instruction'] = str(program.static[rret['address']]['instruction'])

    if 'name' in program.static[rret['address']]:
      #print "setting name"
      rret['name'] = program.static[rret['address']]['name']
    if 'comment' in program.static[rret['address']]:
      rret['comment'] = program.static[rret['address']]['comment']
    elif rret['address'] in program.dwarves:
      rret['comment'] = program.dwarves[rret['address']][2]
    if i in slce:
      rret['slice'] = True
    else:
      rret['slice'] = False
    # for numberless javascript
    rret['address'] = ghex(rret['address'])
    try:
      rret['depth'] = trace.dmap[i - trace.minclnum]
    except:
      rret['depth'] = 0
    ret.append(rret)
  emit('instructions', ret)

@socketio.on('getmemory', namespace='/qira')
@socket_method
def getmemory(forknum, clnum, address, ln):
  trace = program.traces[forknum]
  address = fhex(address)
  dat = trace.fetch_memory(clnum, address, ln)
  ret = {'address': ghex(address), 'len': ln, 'dat': dat, 'is_big_endian': program.tregs[2], 'ptrsize': program.tregs[1]}
  emit('memory', ret)


@socketio.on('getregisters', namespace='/qira')
@socket_method
def getregisters(forknum, clnum):
  trace = program.traces[forknum]
  # register names shouldn't be here
  # though i'm not really sure where a better place is, qemu has this information
  ret = []
  REGS = program.tregs[0]
  REGSIZE = program.tregs[1]

  # 50 is a sane limit here, we don't really need to mark lib calls correctly
  cls = trace.db.fetch_changes_by_clnum(clnum+1, 50)
  regs = trace.db.fetch_registers(clnum)

  for i in range(0, len(REGS)):
    if REGS[i] == None:
      continue
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
    rret['num'] = i
    ret.append(rret)

  emit('registers', ret)

@app.route("/s/<b64search>")
def do_search(b64search):
  results = program.research(base64.b64decode(b64search))
  ret = []
  for r in results:
    swag = r.split(":")
    ln = str(int(swag[1])+1)
    s = '<a class="filelink" onclick=go_to_filename_line("'+swag[0]+'",'+ln+')>' + swag[0]+"#"+ln+"</a>"+":".join(swag[2:])
    ret.append(s)
  return '<br/>'.join(ret)

# *** STATIC CALLS FROM THE FRONTEND ***

@socketio.on('getnames', namespace='/qira')
@socket_method
def getnames(addrs):
  ret = program.static.get_tags(['name'], map(fhex, addrs))
  send = {}
  for addr in ret:
    send[ghex(addr)] = ret[addr]['name']
  emit('names', send)


# TODO: this is a shitty function
@app.route('/gettagsa', methods=["POST"])
@socket_method
def gettagsa():
  arr = json.loads(request.data)
  ret = []
  for i in arr:
    i = fhex(i)

    # always return them all
    # a bit of a hack, this is so javascript can display it
    rret = {}
    for tags in ['name', 'comment']:
      rret[tags] = program.static[i][tags]
    rret['address'] = ghex(i)
    ret.append(rret)
  return json.dumps(ret)

@socketio.on('getstaticview', namespace='/qira')
@socket_method
def getstaticview(haddr, flat, flatrange):
  fxn = program.static[fhex(haddr)]['function']
  if fxn == None:
    return

  blocks = []
  for b in fxn.blocks:
    bb = []
    for i in sorted(b.addresses):
      bbb = {'address': ghex(i)}
      bbb['comment'] = program.static[i]['comment']
      bbb['instruction'] = str(program.static[i]['instruction'])
      bbb['dests'] = map(lambda (x,y): (ghex(x), y), program.static[i]['instruction'].dests())
      bb.append(bbb)
    blocks.append(bb)

  emit('function', {'blocks': blocks})

@socketio.on('gotoname', namespace='/qira')
@socket_method
def gotoname(name):
  addr = program.static.get_address_by_name(name)
  if addr != None:
    emit('setiaddr', ghex(addr))

@socketio.on('settags', namespace='/qira')
@socket_method
def settags(tags):
  for addr in tags:
    naddr = fhex(addr)
    for i in tags[addr]:
      program.static[naddr][i] = tags[addr][i]

# ***** generic webserver stuff *****
  
@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
def serve(path):
  if qira_config.CALLED_AS_CDA and path=="index.html":
    return redirect('/cda')
  # best security?
  if ".." in path:
    return
  ext = path.split(".")[-1]

  try:
    dat = open(qira_config.BASEDIR + "/web/"+path).read()
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


# must go at the bottom
def run_server(largs, lprogram):
  global args
  global program
  global static
  args = largs
  program = lprogram

  if qira_config.WITH_STATIC:
    import qira_static
    qira_static.init_static(program)
  if qira_config.WITH_CDA:
    import cacheserver
    app.register_blueprint(cacheserver.app)
    cacheserver.set_cache(program.cda)

  print "****** starting WEB SERVER on %s:%d" % (qira_config.HOST, qira_config.WEB_PORT)
  threading.Thread(target=mwpoller).start()
  socketio.run(app, host=qira_config.HOST, port=qira_config.WEB_PORT, log=open("/dev/null", "w"))

