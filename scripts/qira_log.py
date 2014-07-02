import struct

IS_VALID = 0x80000000
IS_WRITE = 0x40000000
IS_MEM =   0x20000000
IS_START = 0x10000000
IS_BIGE  = 0x08000000    # not supported
SIZE_MASK = 0xFF

def read_log(fn):
  dat = open(fn).read()

  ret = []
  for i in range(0x18, len(dat), 0x18):
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

