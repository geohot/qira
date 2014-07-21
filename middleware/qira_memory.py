# rewrite this whole thing in c?
import blist

class Address:
  def __init__(this):
    this.backing = blist.sorteddict()

  def fetch(this, clnum):
    kclnum = this.backing.keys().bisect_right(clnum)
    if kclnum == 0:
      return None
    else:
      rclnum = this.backing.keys()[kclnum-1]
      #print this.backing.keys(), clnum, rclnum
      return this.backing[rclnum]

  def commit(this, clnum, dat):
    this.backing[clnum] = dat

class Memory:
  def __init__(this):
    this.daddr = {}
    this.backing = {}

  def copy(this):
    new = Memory()
    new.daddr = this.daddr.copy()
    new.backing = this.backing   # no copy required
    return new

  def fetch(this, clnum, addr, l):
    ret = {}
    for i in range(addr, addr+l):
      if i in this.daddr:
        rret = this.daddr[i].fetch(clnum)
        if rret != None:
          ret[i] = rret
          continue
      # slow
      for (s, e) in this.backing:
        if s <= i and i < e:
          ret[i] = ord(this.backing[(s,e)][i-s])
    return ret

  # backing commit
  def bcommit(this, addr, dat):
    this.backing[(addr, addr+len(dat))] = dat

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

