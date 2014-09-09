# TODO: Switch to an stdio based method instead of needing to TCP server.
import remoteobj

if __name__ == "__main__":
  # Server
  import ctypes, sys
  try:
    remoteobj.CreateServer((sys.argv[1], int(sys.argv[2])), ctypes).handle_request()
  except:
    print 'The remotectypes32 process is angry and quitting.'
    raise
else:
  # Client
  import sys, os, time, subprocess, random
  port = random.randint(10000, 65535)

  if 'PYTHON32' in os.environ:
    p = subprocess.Popen((os.environ['PYTHON32'], __file__, '127.0.0.1', str(port)))
  elif sys.platform == 'darwin':
    p = subprocess.Popen(('/usr/bin/arch', '-i386', '/System/Library/Frameworks/Python.framework/Versions/Current/bin/python2.7', __file__, '127.0.0.1', str(port)))
  else:
    raise Exception('Set PYTHON32 in env to an i386 python.')

  for i in range(4):
    try:
      time.sleep(i/2.0+0.5)
      ctypes = remoteobj.ConnectProxy(('127.0.0.1', port))
      break
    except socket.error:
      x,y,z = sys.exc_info()
  else:
    raise x,y,z

  # Make `from remotectypes32 import *` work as expected
  __all__ = []
  d = ctypes.__dict__
  for k in d:
    if k.startswith('__') and k.endswith('__'): continue
    v = d[k]
    locals()[k] = v
    __all__.append(k)
