#!/usr/bin/env python
# remoteobj v0.2, twice the functionality with half the jank!
import marshal
import struct
import socket
import sys, exceptions, errno, traceback
from types import CodeType
from os import urandom
from hashlib import sha1

class Proxy(object):
  def __init__(self, conn, val):
    object.__setattr__(self, '_proxyconn', conn)
    object.__setattr__(self, '_proxyval', val)
  def __getattribute__(self, attr):
    return object.__getattribute__(self, '_proxyconn').request('get', self, attr)
  def __getattr__(self, attr):
    return object.__getattribute__(self, '_proxyconn').request('get', self, attr)
  def __setattr__(self, attr, val):
    object.__getattribute__(self, '_proxyconn').request('set', self, attr, val)
  def __delattr__(sel, attr):
    object.__getattribute__(self, '_proxyconn').request('get', self, '__delattr__')(attr)
  def __call__(self, *args, **kwargs):
    return object.__getattribute__(self, '_proxyconn').request('call', self, args, kwargs)
  def __del__(self):
    if not marshal or not struct or not socket: return # Reduce spurious messages when quitting python
    try: object.__getattribute__(self, '_proxyconn').request('del', self)
    except socket.error: pass # No need for additional complaints about a dead connection
  def __hash__(self): # __hash__ is weird
    return object.__getattribute__(self, '_proxyconn').request('hash', self)
  
  # Special methods don't always go through __getattribute__, so redirect them all there.
  for special in ('__repr__', '__str__', '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__cmp__', '__rcmp__', '__nonzero__', '__unicode__', '__len__', '__getitem__', '__setitem__', '__delitem__', '__iter__', '__reversed__', '__contains__', '__getslice__', '__setslice__', '__delslice__', '__add__', '__sub__', '__mul__', '__floordiv__', '__mod__', '__divmod__', '__pow__', '__lshift__', '__rshift__', '__and__', '__xor__', '__or__', '__div__', '__truediv__', '__radd__', '__rsub__', '__rmul__', '__rdiv__', '__rtruediv__', '__rfloordiv__', '__rmod__', '__rdivmod__', '__rpow__', '__rlshift__', '__rrshift__', '__rand__', '__rxor__', '__ror__', '__iadd__', '__isub__', '__imul__', '__idiv__', '__itruediv__', '__ifloordiv__', '__imod__', '__ipow__', '__ilshift__', '__irshift__', '__iand__', '__ixor__', '__ior__', '__neg__', '__pos__', '__abs__', '__invert__', '__complex__', '__int__', '__long__', '__float__', '__oct__', '__hex__', '__index__', '__coerce__', '__enter__', '__exit__'):
    exec 'def {special}(self, *args, **kwargs):\n\treturn getattr(self, "{special}")(*args, **kwargs)'.format(special=special) in None, None

class Connection(object):
  def __init__(self, sock, secret, endpoint = urandom(8).encode('hex')):
    self.sock = sock
    self.secret = secret
    self.endpoint = endpoint

  def runServer(self, obj):
    if self.sock.recv(2) != 'yo': return
    self.sock.sendall(sha1(self.secret+self.sock.recv(20)).digest())
    chal = urandom(20)
    self.sock.sendall(chal)
    if self.sock.recv(20) != sha1(self.secret+chal).digest(): return
    try:
      self.vended = {}
      self.sendmsg(self.pack(obj))
      while self.vended:
        self.handle(self.recvmsg())
    except socket.error as e:
      if e.errno in (errno.EPIPE, errno.ECONNRESET): pass # Client disconnect is a non-error.
      else: raise
    finally:
      del self.vended

  def connectProxy(self):
    self.vended = {}
    self.sock.sendall('yo')
    chal = urandom(20)
    self.sock.sendall(chal)
    if self.sock.recv(20) != sha1(self.secret+chal).digest(): return
    self.sock.sendall(sha1(self.secret+self.sock.recv(20)).digest())
    return self.unpack(self.recvmsg())

  def handle(self, msg):
    #print msg
    try:
      if msg[0] == 'get':
        _, obj, attr = msg
        reply = ('ok', self.pack(getattr(self.unpack(obj), attr)))
      elif msg[0] == 'set':
        _, obj, attr, val = msg
        setattr(self.unpack(obj), attr, self.unpack(val))
        reply = ('ok', None)
      elif msg[0] == 'call':
        _, obj, args, kwargs = msg
        reply =  ('ok', self.pack(self.unpack(obj)(*self.unpack(args), **self.unpack(kwargs))))
      elif msg[0] == 'del':
        try:
          _, obj = msg
          k = id(self.unpack(obj))
          self.vended[k][1] -= 1
          if self.vended[k][1] == 0:
            del self.vended[k]
        except:
          print "Exception while deleting", msg[1]
          traceback.print_exc()
        reply = ('ok', None)
      elif msg[0] == 'hash':
        _, obj = msg
        reply = ('ok', self.pack(hash(self.unpack(obj))))
      else:
        assert False, "Bad message " + repr(x) # Note that this gets caught
    except:
      typ, val, tb = sys.exc_info()
      reply = ('exn', typ.__name__, self.pack(val.args), traceback.format_exception(typ, val, tb))
    
    self.sendmsg(reply)

  def request(self, method, proxy, *args):
    self.sendmsg((method, object.__getattribute__(proxy, '_proxyval'))+tuple(self.pack(i) for i in args))
    while True:
      x = self.recvmsg()
      if x[0] == 'ok':
        return self.unpack(x[1])
      elif x[0] == 'exn':
        exntyp = exceptions.__dict__.get(x[1])
        args = self.unpack(x[2])
        trace = x[3]
        if exntyp and issubclass(exntyp, BaseException):
          e = exntyp(*(args + ('Remote '+''.join(trace),)))
          raise e
        else:
          raise Exception(str(x[1])+repr(args)+'\nRemote '+''.join(trace))
      else:
        self.handle(x)

  # Note: must send after packing, or objects will be left with +1 retain count in self.vended
  def pack(self, val):
    if type(val) in (bool, int, long, float, complex, str, unicode, StopIteration, Ellipsis):
      return val
    elif type(val) == tuple:
      return tuple(self.pack(i) for i in val)
    elif type(val) == list:
      return [self.pack(i) for i in val]
    elif type(val) == set:
      return {self.pack(i) for i in val}
    elif type(val) == frozenset:
      return frozenset(self.pack(i) for i in val)
    elif type(val) == dict:
      return {self.pack(k):self.pack(v) for k,v in val.iteritems()}
    elif type(val) == Proxy:
      return object.__getattribute__(val, '_proxyval')
    #elif type(val) == CodeType:
    # Just send code self.vended via proxy
    else:
      self.vended.setdefault(id(val), [val, 0])[1] += 1
      return (StopIteration, Ellipsis, self.endpoint, id(val))

  def unpack(self, val):
    if type(val) == tuple and len(val) == 4 and val[:2] == (StopIteration, Ellipsis):
      if val[2] == self.endpoint:
        try:
          return self.vended[val[3]][0]
        except KeyError:
          raise Exception("Whoops, "+self.endpoint+" can't find reference to object "+repr(val[3]))
      else:
        return Proxy(self, val)
    elif type(val) == tuple:
      return tuple(self.unpack(i) for i in val)
    elif type(val) == list:
      return [self.unpack(i) for i in val]
    elif type(val) == set:
      return {self.unpack(i) for i in val}
    elif type(val) == frozenset:
      return frozenset(self.unpack(i) for i in val)
    elif type(val) == dict:
      return {self.unpack(k):self.unpack(v) for k,v in val.iteritems()}
    elif type(val) == CodeType:
      raise Exception('code types get proxied')
    else:
      return val

  def sendmsg(self, msg):
    x = marshal.dumps(msg)
    self.sock.sendall(struct.pack('<I', len(x)))
    self.sock.sendall(x)

  def recvmsg(self):
    x = self.sock.recv(4)
    if len(x) == 4:
      y = struct.unpack('<I', x)[0]
      z = self.sock.recv(y)
      if len(z) == y:
        return marshal.loads(z)
    raise socket.error(errno.ECONNRESET, 'The socket was closed while receiving a message.')

__all__ = [Connection,]

# For demo purposes.
if __name__ == "__main__":
  from sys import argv
  if len(argv) <= 3:
    print "Usage:", argv[0], "server <address> <port> [<password>]"
    print "       python -i", argv[0], "client <address> <port> [<password>]"
    print "In the client python shell, the server's module is available as 'proxy'"
    print "A good demo is `proxy.__builtins__.__import__('ctypes').memset(0,0,1)`"
    exit(64)
  
  hostport = (argv[2], int(argv[3]))
  password = argv[4] if len(argv) > 4 else 'lol, python'
  if argv[1] == 'server':
    import SocketServer
    class Server(SocketServer.BaseRequestHandler):
      def handle(self):
        print 'Accepting client', self.client_address
        Connection(self.request, password).runServer(sys.modules[__name__])
        print 'Finished with client', self.client_address
    SocketServer.TCPServer.allow_reuse_address = True
    SocketServer.TCPServer(hostport, Server).serve_forever()
    exit(1)
  elif argv[1] == 'client':
    proxy = Connection(socket.create_connection(hostport), password).connectProxy()
  else:
    exit(64)
