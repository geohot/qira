import remoteobj

ADDR = ('localhost', 43673)
PYTHON32 = ''

if __name__ == "__main__":
  # Server
  import ctypes
  try:
    remoteobj.CreateServer(ADDR, ctypes).handle_request()
  except:
    print 'The remotectypes32 process is angry and quitting.'
    raise
else:
  # Client
  import subprocess
  import time
  if not PYTHON32:
    raise Exception('Please set PYTHON32 in remotectypes32.py and pretend that nothing ghetto is happening.')
  p = subprocess.Popen((PYTHON32, __file__))
  time.sleep(0.1)
  ctypes = remoteobj.ConnectProxy(ADDR)
  __all__ = []
  d = ctypes.__dict__
  for k in d:
    if k.startswith('__') and k.endswith('__'): continue
    v = d[k]
    locals()[k] = v
    __all__.append(k)
