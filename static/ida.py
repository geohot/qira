#!/usr/bin/env python2.7
import sys
import os
import struct
from ida_consts import *
import time

# ugh, qira_base
def ghex(a):
  if a == None:
    return None
  return hex(a).strip("L")

def fhex(a):
  try:
    return int(a, 16)
  except:
    return None

# fixes the help issue
os.environ['PATH'] += ":"+IDAPATH
os.environ['LD_LIBRARY_PATH'] = IDAPATH
os.environ['IDADIR'] = IDAPATH

if sys.maxsize > 2**32:
  if __name__ == "__main__":
    print "relaunching as 32-bit python"
    os.system("python32/Python/python "+__file__+" "+" ".join(sys.argv[1:]))
    exit(0)
  from remotectypes32 import *
else:
  from ctypes import *
  def remote_func(x):
    return x

done = False
argc = 1
argv = None
idle_fxn = None

CALLUI = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
def set_done(b):
  global done
  done = b
def set_idle_fxn(f):
  global idle_fxn
  idle_fxn = f
def uicallback(a,b,c,d,e,f,g,h,i):
  b_ptr = cast(b, POINTER(c_long))
  b_ptr[0] = 0

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
      set_done(True)
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
    set_idle_fxn(CFUNCTYPE(c_int)(d))
  if c == 25:
    print "ask_file:",cast(e, c_char_p).value.strip(),cast(f, c_char_p).value.strip()
    global buf   # OMG GC
    buf = create_string_buffer(FILE)
    b_ptr[0] = addressof(buf)
    #b_ptr[0] = 0xAABBCCDD
  return 0

def run_ida():
  global done
  done = False
  while not done:
    idle_fxn()
  print "*** run_ida finished"

def fetch_tags():
  import collections
  tags = collections.defaultdict(dict)

  for i in range(0, ida.get_nlist_size()):
    ea = ida.get_nlist_ea(i)
    name = c_char_p(ida.get_nlist_name(i)).value.strip()
    #print hex(ea), name
    tags[ea]['name'] = name

  def parse_addr(i):
    flags = ida.get_flags_ex(i, 0)
    # is code
    if (flags&0x600) == 0x600:
      print ghex(i)
      tags[i]['flags'] = flags
      tags[i]['flow'] = []
      tags[i]['semantics'] = []
      tags[i]['len'] = ida.decode_insn(i)
      if ida.is_call_insn(i):
        tags[i]['semantics'].append("call")
      if ida.is_ret_insn(i, 1):
        tags[i]['semantics'].append("ret")
      if ida.is_basic_block_end(0):
        tags[i]['semantics'].append("endbb")
      #print ghex(i), tags[ghex(i)]['len']
    return flags

  i = 0
  while 1:
    i = ida.nextaddr(i)
    if i == -0x1:
      break
    parse_addr(i)

  fxn_count = ida.get_func_qty()
  for i in range(0, fxn_count):
    #print i
    fxn = cast(ida.getn_func(i), POINTER(c_long))
    fxn = [fxn[0], fxn[1]]
    tags[fxn[0]]['funclength'] = fxn[1]-fxn[0]
    #print hex(fxn[0]), hex(fxn[1])

    # get the flags for each address in the function
    for i in range(fxn[0], fxn[1]):
      # this should be the only thing set here
      #flags = parse_addr(i)
      flags = ida.get_flags_ex(i, 0)
      if (flags&0x600) == 0x600:
        tags[i]['scope'] = ghex(fxn[0])
        cref = ida.get_first_fcref_from(i)
        while cref != -1:
          if cref >= fxn[0] and cref < fxn[1]:
            tags[i]['flow'].append(ghex(cref))
          #print "   ",ghex(cref)
          cref = ida.get_next_fcref_from(i, cref)

  return tags


def set_name(ea, name):
  ida.set_name(ea, create_string_buffer(name), 0)

def set_comment(ea, text):
  # all repeatable
  ida.set_cmt(ea, create_string_buffer(text), 1)

def get_name(ea):
  # TODO(ryan): why do i have to malloc here?
  tmp = libc.malloc(80)
  #tmp = create_string_buffer(80)
  ida.get_name.restype=c_char_p
  ret = ida.get_name(BADADDR, ea, tmp, 80)
  if ret != None:
    return ret
  return None

def get_name_ea(name):
  ea = ida.get_name_ea(BADADDR, create_string_buffer(name))
  if ea == BADADDR:
    return None
  return ea

def init_with_binary(filename):
  global ida, libc, FILE

  FILE = "/tmp/qida/ida_binary"
  os.system("rm -rf /tmp/qida; mkdir -p /tmp/qida")
  os.system("cp "+filename+" "+FILE)

  if sys.platform == 'darwin':
    ida = cdll.LoadLibrary(IDAPATH+"/libida.dylib")
    libc = cdll.LoadLibrary("libc.dylib")
  elif sys.platform == 'win32':
    print 'TODO: windows support'
    return False
  else:
    # Linux
    ida = cdll.LoadLibrary(IDAPATH+"/libida.so")
    libc = cdll.LoadLibrary("libc.so.6")

  fxn = CALLUI(remote_func(uicallback))
  # how hack is that, KFC
  rsc = "\xB9"+struct.pack("I", cast(fxn, c_void_p).value)+"\xFF\xD1\x59\x83\xC4\x04\xFF\xE1"
  sc = create_string_buffer(rsc)
  libc.mprotect(addressof(sc) & 0xFFFFF000, 0x1000, 7)
  print "*** ida.init_kernel", ida.init_kernel(sc, argc, argv)
  newfile = c_int(0)
  print "*** ida.init_database", ida.init_database(argc, argv, pointer(newfile))
  run_ida()

if __name__ == "__main__":
  init_with_binary(sys.argv[1])

