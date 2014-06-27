from qira_log import *
import json

class Address:
  def __init__(this):
    this.backing = {}

  def commit(this, clnum, dat):
    this.backing[clnum] = dat

class Memory:
  def __init__(this):
    this.daddr = {}

  def dump(this):
    ret = {}
    for i in this.daddr:
      ret[i] = this.daddr[i].backing
    return ret

  def commit(this, clnum, addr, dat):
    if addr not in this.daddr:
      this.daddr[addr] = Address()
    this.daddr[addr].commit(clnum, dat)

regs = Memory()
mem = Memory()

def init():
  dat = read_log("/tmp/qira_log")
  for (address, data, clnum, flags) in dat:
    if flags & IS_WRITE and flags & IS_MEM:
      size = flags & SIZE_MASK
      # support big endian
      for i in range(0, size/8):
        mem.commit(clnum, address+i, data & 0xFF)
        data >>= 8
    elif flags & IS_WRITE:
      size = flags & SIZE_MASK
      # support big endian
      regs.commit(clnum, address, data)

if __name__ == '__main__':
  init()
  print "init done"
  dat = {"regs": regs.dump(), "mem": mem.dump()}
  open("/tmp/qira_memdb", "wb").write(json.dumps(dat))
  print "json extracted"

