#!/home/vagrant/build/Python-2.7.8/python
import os
from ctypes import *
IDAPATH = "/home/vagrant/idademo66/"
FILE = "/home/vagrant/qira/tests/a.out"

#os.chdir(IDAPATH)
ida = cdll.LoadLibrary(IDAPATH+"libida.so")

CALLUI = CFUNCTYPE(c_int, POINTER(c_void_p), c_void_p)
def uicallback(a,b):
  print "callback",a,b
  print a[0], a[1], a[2], a[3], a[4]
  return 0

print ida.init_kernel(CALLUI(uicallback), 0, None)
exit(0)

linput = ida.open_linput(FILE, False)
print "loaded file",hex(linput)

NEF_FIRST = 0x80
ret = ida.load_nonbinary_file(FILE, linput, ".", NEF_FIRST, None)
print "load_nonbinary_file", ret



