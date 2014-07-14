import time
import socket
import signal
from pymongo import MongoClient
import json

# communication through a file like this is bad
def write_memdb(regs, mem):
  open("/tmp/qira_memdb", "wb").write(
    json.dumps({"regs": regs.dump(), "mem": mem.dump()}))

meteor_pid = -1

def db_push(db_changes, db_pmaps):
  db = mongo_connect()
  Change = db.change
  Pmaps = db.pmaps

  if len(db_pmaps) > 0:
    Pmaps.insert(db_pmaps)
  pmaps = new_pmaps

  # push changes to db
  if len(db_changes) > 0:
    Change.insert(db_changes)
  db.connection.close()


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


def meteor_init(is_managing_meteor):
  # connect to db, set up collections, and drop
  if is_managing_meteor:
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

