#!/usr/bin/env python
# This isn't perfect. For example, do not run help(proxy).

import marshal
import struct
import socket
import exceptions
import sys
from types import CodeType
import SocketServer

# The server is open for code exec, and the client is likely exploitable,
# so be super secure in both directions.
secret = "lol, python"

from hashlib import sha1
from os import urandom

def ClientHandshake(sock):
  sock.sendall('yo')
  chal = urandom(20)
  sock.sendall(chal)
  if sock.recv(20) != sha1(secret+chal).digest(): return False
  sock.sendall(sha1(secret+sock.recv(20)).digest())
  return True

def ServerHandshake(sock):
  if sock.recv(2) != 'yo': return False
  sock.sendall(sha1(secret+sock.recv(20)).digest())
  chal = urandom(20)
  sock.sendall(chal)
  if sock.recv(20) != sha1(secret+chal).digest(): return False
  return True

def sendmsg(sock, obj):
  x = marshal.dumps(obj)
  sock.sendall(struct.pack('<I', len(x)))
  sock.sendall(x)

import errno
def recvmsg(sock):
  x = sock.recv(4)
  if len(x) < 4:
    raise socket.error(errno.EPIPE, 'The socket was closed mid-message.')
  y = struct.unpack('<I', x)[0]
  z = sock.recv(y)
  if len(z) < y:
    raise socket.error(errno.EPIPE, 'The socket was closed mid-message.')
  return marshal.loads(z)

class Proxy(object):
  __slots__ = ('_proxymsgsend',)
  def __init__(self, conn, proxyid):
    def pack(val):
      if type(val) in (bool, int, long, float, complex, str, unicode):
        return val
      elif type(val) == tuple:
        return tuple(pack(i) for i in val)
      elif type(val) == list:
        return [pack(i) for i in val]
      elif type(val) == set:
        return {pack(i) for i in val}
      elif type(val) == frozenset:
        return frozenset(pack(i) for i in val)
      elif type(val) == dict:
        return {pack(k):pack(v) for k,v in val.iteritems()}
      elif type(val) == Proxy:
        return (StopIteration, Ellipsis, val._id)
      elif type(val) == CodeType:
        raise Exception('no')
      else:
        raise Exception("Can't send object "+repr(val)+" to the remote server.")
    
    def unpack(val):
      if type(val) == tuple and len(val) == 3 and val[:2] == (StopIteration, Ellipsis):
        return Proxy(conn, val)
      elif type(val) == tuple:
        return tuple(unpack(i) for i in val)
      elif type(val) == list:
        return [unpack(i) for i in val]
      elif type(val) == set:
        return {unpack(i) for i in val}
      elif type(val) == frozenset:
        return frozenset(unpack(i) for i in val)
      elif type(val) == dict:
        return {unpack(k):unpack(v) for k,v in val.iteritems()}
      elif type(val) == CodeType:
        raise Exception('no')
      else:
        return val
    
    def msgsend(method, *args):
      sendmsg(conn, (method, proxyid)+pack(tuple(args)))
      x = recvmsg(conn)
      if x[0] == 'ok':
        return unpack(x[1])
      elif x[0] == 'exn':
        exntype = exceptions.__dict__.get(x[1])
        if exntype and issubclass(exntype, BaseException):
          raise exntype, exntype(*unpack(x[2])), None
        else:
          raise Exception, Exception(str(x[1])+repr(unpack(x[2]))), None
      else:
        assert False, "Bad response " + repr(x)
    
    object.__setattr__(self, '_proxymsgsend', msgsend)
    
  def __getattribute__(self, attr):
    return object.__getattribute__(self, '_proxymsgsend')('get', attr)
  def __getattr__(self, attr):
    return object.__getattribute__(self, '_proxymsgsend')('get', attr)
  def __setattr__(self, attr, val):
    object.__getattribute__(self, '_proxymsgsend')('set', attr, val)
  def __delattr__(sel, attr):
    object.__getattribute__(self, '_proxymsgsend')('get', '__delattr__')(attr)
  def __call__(self, *args, **kwargs):
    return object.__getattribute__(self, '_proxymsgsend')('call', args, kwargs)
  def __del__(self):
    object.__getattribute__(self, '_proxymsgsend')('del')
  def __hash__(self): # __hash__ is weird
    return object.__getattribute__(self, '_proxymsgsend')('hash')
  # Special methods don't always go through __getattribute__
  for special in ('__repr__', '__str__', '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__cmp__', '__rcmp__', '__nonzero__', '__unicode__', '__len__', '__getitem__', '__setitem__', '__delitem__', '__iter__', '__reversed__', '__contains__', '__getslice__', '__setslice__', '__delslice__', '__add__', '__sub__', '__mul__', '__floordiv__', '__mod__', '__divmod__', '__pow__', '__lshift__', '__rshift__', '__and__', '__xor__', '__or__', '__div__', '__truediv__', '__radd__', '__rsub__', '__rmul__', '__rdiv__', '__rtruediv__', '__rfloordiv__', '__rmod__', '__rdivmod__', '__rpow__', '__rlshift__', '__rrshift__', '__rand__', '__rxor__', '__ror__', '__iadd__', '__isub__', '__imul__', '__idiv__', '__itruediv__', '__ifloordiv__', '__imod__', '__ipow__', '__ilshift__', '__irshift__', '__iand__', '__ixor__', '__ior__', '__neg__', '__pos__', '__abs__', '__invert__', '__complex__', '__int__', '__long__', '__float__', '__oct__', '__hex__', '__index__', '__coerce__', '__enter__', '__exit__'):
    exec 'def {special}(self, *args, **kwargs):\n\treturn getattr(self, "{special}")(*args, **kwargs)'.format(special=special)

def ConnectProxy((host, port)):
  sock = socket.create_connection((host, port))
  assert ClientHandshake(sock)
  x = recvmsg(sock)
  assert x[:2] == (StopIteration, Ellipsis)
  return Proxy(sock, x)

class Server(SocketServer.BaseRequestHandler):
  def pack(self, val):
    if type(val) in (bool, int, long, float, complex, str, unicode):
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
    # elif type(val) == CodeType: Actually, send code objects via proxy.
    #   raise Exception('no')
    else:
      self.objects.setdefault(id(val), [val, 0])[1] += 1
      return (StopIteration, Ellipsis, id(val))

  def unpack(self, val):
    if type(val) == tuple and len(val) == 3 and val[:2] == (StopIteration, Ellipsis):
      try:
        return self.objects[val[2]][0]
      except KeyError:
        raise Exception("Whoops, server can't find reference to object "+repr(val[2]))
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
      raise Exception('no')
    else:
      return val

  def handle_msg(self, msg):
    try:
      if msg[0] == 'get':
        _, obj, attr = msg
        return ('ok', self.pack(getattr(self.unpack(obj), attr)))
      elif msg[0] == 'set':
        _, obj, attr, val = msg
        setattr(self.unpack(obj), attr, self.unpack(val))
        return ('ok', None)
      elif msg[0] == 'call':
        _, obj, args, kwargs = msg
        return ('ok', self.pack(self.unpack(obj)(*self.unpack(args), **self.unpack(kwargs))))
      elif msg[0] == 'del':
        _, (_, _, objid) = msg
        try:
          t = self.objects[objid]
          t[1] -= 1
          if t[1] == 0:
            #print 'deleting', objid, repr(self.objects[objid]), ' ', len(self.objects), 'items left'
            del self.objects[objid]
        except:
          print "Huh, couldn't find a", objid, "to delete."
        return ('ok', None)
      elif msg[0] == 'hash':
        _, obj = msg
        return ('ok', self.pack(hash(self.unpack(obj))))
      else:
        assert False, "Bad message " + repr(x)
    except BaseException, e:
      return ('exn', type(e).__name__, self.pack(e.args))

  def handle(self):
    try:
      if not ServerHandshake(self.request): return
      self.objects = {id(self.server.object):[self.server.object, 1]}
      sendmsg(self.request, (StopIteration, Ellipsis, id(self.server.object)))
      while self.objects:
        sendmsg(self.request, self.handle_msg(recvmsg(self.request)))
    finally:
      del self.objects

def CreateServer((host, port), obj):
  SocketServer.TCPServer.allow_reuse_address = True # pls
  server = SocketServer.TCPServer((host, port), Server)
  server.object = obj
  return server

__all__ = [ConnectProxy, CreateServer]

# For demo purposes. A good example is proxy.__builtins__.__import__('ctypes').memset(0,0,1)
if __name__ == "__main__":
  from sys import argv
  if len(argv) <= 3:
    print "Usage:", argv[0], "server <address> <port>"
    print "       python -i", argv[0], "client <address> <port>"
    print "In the client python shell, the server's module is available as 'proxy'"
    exit(64)
  elif argv[1] == 'server':
    CreateServer((argv[2], int(argv[3])), sys.modules[__name__]).serve_forever()
    exit(1)
  elif len(argv) > 3 and argv[1] == 'client':
    proxy = ConnectProxy((argv[2], int(argv[3])))
  else:
    exit(64)
