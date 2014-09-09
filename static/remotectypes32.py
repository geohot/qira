# TODO: Switch to an stdio based method instead of needing to TCP server.
import remoteobj
import socket

if __name__ == "__main__":
  # Server
  try:
    from sys import argv
    remoteobj.Connection(socket.create_connection((argv[1], int(argv[2]))), argv[3]).runServer(__import__('ctypes'))
  except:
    print 'The remotectypes32 process is angrily exiting.'
    raise
else:
  # Client
  import sys, os, time, subprocess, random
  port = random.randint(10000, 65535)
  secret = os.urandom(20).encode('hex')
  
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.bind(('127.0.0.1', port))
  sock.listen(1)
  
  args = (__file__, '127.0.0.1', str(port), secret)
  if 'PYTHON32' in os.environ:
    p = subprocess.Popen((os.environ['PYTHON32'],)+args)
  elif sys.platform == 'darwin':
    p = subprocess.Popen(('/usr/bin/arch', '-i386', '/System/Library/Frameworks/Python.framework/Versions/Current/bin/python2.7')+args)
  else:
    raise Exception('Set env variable PYTHON32 to an i386 python.')

  conn, addr = sock.accept()
  ctypes = remoteobj.Connection(conn, secret).connectProxy()

  # Make `from remotectypes32 import *` work as expected
  __all__ = []
  d = ctypes.__dict__
  for k in d:
    if k.startswith('__') and k.endswith('__'): continue
    v = d[k]
    locals()[k] = v
    __all__.append(k)
