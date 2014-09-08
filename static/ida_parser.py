#!/home/vagrant/idademo66/python

# copied python into ida demo folder
# also symlinked libida.so to /usr/lib/libida.so for early loads to work

import sys
import os
import struct
from ctypes import *
from ida_consts import *
import time

FILE = "/tmp/qida/ida_binary"
os.system("rm -rf /tmp/qida; mkdir -p /tmp/qida")
os.system("cp "+sys.argv[1]+" "+FILE)

done = False

#argc = 2
#string_buffers = [create_string_buffer(""), create_string_buffer(FILE)]
#argv = (c_char_p*3)(*map(addressof, string_buffers)+[0])
argc = 1
argv = None
idle_fxn = None


#os.chdir(IDAPATH)
ida = cdll.LoadLibrary(IDAPATH+"libida.so")
libc = cdll.LoadLibrary("libc.so.6")

CALLUI = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
def uicallback(a,b,c,d,e,f,g,h,i):
  global done
  b_ptr = cast(b, POINTER(c_long))
  b_ptr[0] = 0

  global idle_fxn
  if c == 17: # ui_banner
    b_ptr[0] = 1
    return 0
  elif c == 28: # ui_clearbreak
    return 0
  elif c == 29: # ui_wasbreak
    # ui_wasbreak, always return 0
    return 0
  #print "callback",a,b,c,d,e,f
  #return 0
  elif c == 23:
    #st = cast(d, c_char_p).value.strip()
    #print st
    """
    if "%s" in st and f != None:
      print cast(f, c_char_p).value.strip()
    """
    #print cast(f, c_char_p).value
    libc.vprintf(d, e)
    return 0
  elif c == 21:
    # MBOX
    libc.vprintf(e, f)
    print ""
    return 0

  elif c == 50:
    if d == None:
      d = 0
    if d == 527:
      # WTF USELESS?
      return 0
    if d == 53: # auto_empty_finally
      done = True
      return 0
    if d < len(idp_notify):
      #print "idp_notify",d,idp_notify[d]
      pass
    else:
      return 0
      #print "idp_notify",d

    #st = struct.unpack("I", cast(e, c_char_p).value[0:4])[0]
    #print cast(st, c_char_p).value.strip()
    #ret = ida.invoke_callbacks(0, d, e)
    #print "RETURN 0"
    # ugh hacks
    b_ptr[0] = 0
    """
    if d == 2 or d == 3:
      print "returning 1"
      libc.memset(b, 1, 1)
    #if d == 0 or d == None:
      libc.memset(b, 0, 4)
    elif d == 4:
      print "newfile",cast(e, c_char_p).value.strip()
    """
    #print cast(b, POINTER(c_int)).contents
    #print cast(b, POINTER(c_int)).contents
    return 1

  print "callback", ui_msgs[c], c,d,e,f,g,h,i

  if c == 43:
    print "load_file:",cast(d, c_char_p).value.strip(), hex(e), hex(f)
    b_ptr[0] = 1
    lst = ida.build_loaders_list(e)
    print "loaders_list", hex(lst)
    ret = ida.load_nonbinary_file(FILE, e, ".", NEF_FIRST, lst)
    print ret
    #ida.init_loader_options(e, lst)
  if c == 18:
    print "got set idle",d
    idle_fxn = CFUNCTYPE(c_int)(d)
  if c == 25:
    print "ask_file:",cast(e, c_char_p).value.strip(),cast(f, c_char_p).value.strip()
    global buf   # OMG GC
    buf = create_string_buffer(FILE)
    b_ptr[0] = addressof(buf)
    #b_ptr[0] = 0xAABBCCDD
  return 0

fxn = CALLUI(uicallback)
# how hack is that, KFC
rsc = "\xB9"+struct.pack("I", cast(fxn, c_void_p).value)+"\xFF\xD1\x59\x83\xC4\x04\xFF\xE1"
sc = create_string_buffer(rsc)
print "mprotect", libc.mprotect(addressof(sc) & 0xFFFFF000, 0x1000, 7)
print "init_kernel", ida.init_kernel(sc, argc, argv)
#print "init_kernel", ida.init_kernel(CALLUI(uicallback), 0, None)
newfile = c_int(0)

print "init_database", ida.init_database(argc, argv, pointer(newfile))
#print "init_database", ida.init_database(1, None, pointer(newfile))
print newfile

while not done:
  idle_fxn()

# ******************** USER TIME ********************

import collections

def ghex(a):
  if a == None:
    return None
  return hex(a).strip("L")

tags = collections.defaultdict(dict)

for i in range(0, ida.get_nlist_size()):
  ea = ida.get_nlist_ea(i)
  name = cast(ida.get_nlist_name(i), c_char_p).value.strip()
  print hex(ea), name
  tags[ghex(ea)]['name'] = name

for i in range(0, ida.get_func_qty()):
  print i
  fxn = cast(ida.getn_func(i), POINTER(c_long))
  tags[ghex(fxn[0])]['funclength'] = fxn[1]-fxn[0]

  print hex(fxn[0]), hex(fxn[1]), fxn[2], fxn[3]

  # get the flags for each address in the function
  for i in range(fxn[0], fxn[1]):
    flags = ida.get_flags_ex(i, 0)
    #print hex(flags)
    # is code
    ida.gen_flow_graph(create_string_buffer("/tmp/qida/fxn_"+ghex(fxn[0])), create_string_buffer("yolo"), fxn, None, None, 0x3000) 
    if (flags&0x600) == 0x600:
      tags[ghex(i)]['scope'] = ghex(fxn[0])
      tags[ghex(i)]['flags'] = flags


# upload the tags

import json
tags = dict(tags)
print tags
open("/tmp/qida/tags", "wb").write(json.dumps({"tags": tags}))

"""
from socketIO_client import SocketIO, BaseNamespace
class QiraNamespace(BaseNamespace):
  pass

sio = SocketIO('localhost', 3002)
qira = sio.define(QiraNamespace, '/qira')
qira.emit("settags", dict(tags))
"""

# ******************** USER DONE ********************

ida.term_database()

exit(0)


