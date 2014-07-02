import struct

IS_VALID = 0x80000000
IS_WRITE = 0x40000000
IS_MEM =   0x20000000
IS_START = 0x10000000
IS_BIGE  = 0x08000000    # not supported
SIZE_MASK = 0xFF

LOGFILE = "/tmp/qira_log"

def flag_to_type(flags):
  if flags & IS_START:
    typ = "I"
  elif flags & IS_WRITE and flags & IS_MEM:
    typ = "S"
  elif not flags & IS_WRITE and flags & IS_MEM:
    typ = "L"
  elif flags & IS_WRITE and not flags & IS_MEM:
    typ = "W"
  elif not flags & IS_WRITE and not flags & IS_MEM:
    typ = "R"
  return typ

def get_log_length(fn):
  dat = open(fn).read(4)
  return struct.unpack("I", dat)[0]

def read_log(fn, seek=1, cnt=0):
  f = open(fn)
  f.seek(seek*0x18)
  if cnt == 0:
    dat = f.read()
  else:
    dat = f.read(cnt * 0x18)

  ret = []
  for i in range(0, len(dat), 0x18):
    (address, data, clnum, flags) = struct.unpack("QQII", dat[i:i+0x18])
    if not flags & IS_VALID:
      break
    ret.append((address, data, clnum, flags))

  return ret

def write_log(fn, dat):
  # untested
  ss = [struct.pack("I", len(dat)) + "\x00"*0x14]
  for (address, data, clnum, flags) in dat:
    ss.append(struct.pack("QQII", address, data, clnum, flags))
  f = open(fn, "wb")
  f.write(''.join(ss))
  f.close()

