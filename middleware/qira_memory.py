import blist

class Address:
  def __init__(this):
    this.backing = blist.sorteddict()

  def fetch(this, clnum):
    rclnum = this.backing.bisect_left(clnum)
    if rclnum == None:
      return None
    else:
      return this.backing[rlcnum]

  def commit(this, clnum, dat):
    this.backing[clnum] = dat

class Memory:
  def __init__(this):
    this.daddr = {}

  def fetch(this, clnum, addr, l):
    ret = {}
    for i in range(addr, addr+l):
      if i in this.daddr:
        ret[i] = this.daddr[i].fetch(clnum)
    return ret

  def dump(this):
    ret = {}
    for i in this.daddr:
      rret = {}
      for j in this.daddr[i].backing:
        rret[j] = this.daddr[i].backing[j]
      ret[i] = rret
    return ret

  def commit(this, clnum, addr, dat):
    if addr not in this.daddr:
      this.daddr[addr] = Address()
    this.daddr[addr].commit(clnum, dat)

