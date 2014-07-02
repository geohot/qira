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

