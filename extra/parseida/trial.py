#!/home/vagrant/idademo66/python
import os
from ctypes import *
import time
IDAPATH = "/home/vagrant/idademo66/"
FILE = "/home/vagrant/qira/tests/a.out"

#os.chdir(IDAPATH)
ida = cdll.LoadLibrary(IDAPATH+"libida.so")
libc = cdll.LoadLibrary("libc.so.6")

"""
CALLUI = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p)
def uicallback(a,b,c):
  print "callback",a,b,hex(c)
  return 0
"""

# how hack is that, KFC
rsc = "\x59\x31\xC0\x83\xC4\x04\xFF\xE1"
sc = create_string_buffer(rsc)
print "mprotect", libc.mprotect(addressof(sc) & 0xFFFFF000, 0x1000, 7)
print "init_kernel", ida.init_kernel(sc, 0, None)
newfile = c_int(0)
print "init_database", ida.init_database(1, create_string_buffer("\x00"*4), pointer(newfile))
print newfile

linput = ida.open_linput(FILE, False)
print "loaded file",hex(linput)

NEF_FIRST = 0x80
ret = ida.load_nonbinary_file(FILE, linput, ".", NEF_FIRST, None)
print "load_nonbinary_file", ret

print "save_database_ex", ida.save_database_ex("/tmp/test.idb", 0, None, None)


