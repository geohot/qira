from Trace.Trace cimport Trace

# copied from Trace.h
SIZE_MASK = 0xFF
PAGE_INSTRUCTION = 1
PAGE_READ = 2
PAGE_WRITE = 4

MAXINT = 2**32-1

cdef class PyTrace:
  cdef Trace *t

  def __cinit__(self, filename, trace_index, register_size, register_count, is_big_endian):
    self.t = new Trace()
    assert self.t.ConnectToFileAndStart(filename.encode('utf-8'), trace_index, register_size, register_count, is_big_endian)

  def __dealloc__(self):
    del self.t

  def get_maxclnum(self):
    return self.t.GetMaxClnum()

  def get_minclnum(self):
    return self.t.GetMinClnum()

  def did_update(self):
    return self.t.GetDidUpdate()

  def get_pmaps(self):
    ret = {}
    pagemap = self.t.GetPages()
    for address,ttype in pagemap:
      if ttype & PAGE_INSTRUCTION:
        ret[address] = "instruction"
      elif ttype & PAGE_WRITE:
        ret[address] = "memory"
      elif ttype & PAGE_READ:
        ret[address] = "romemory"
    return ret

  def fetch_clnums_by_address_and_type(self, address, ttype, start_clnum, end_clnum, limit):
    return self.t.FetchClnumsByAddressAndType(address, ord(ttype), start_clnum, end_clnum, limit)

  def fetch_registers(self, clnum):
    if clnum == -1:   # fetch the latest
      clnum = MAXINT
    return self.t.FetchRegisters(clnum)

  def fetch_memory(self, clnum, address, llen):
    if clnum == -1:   # fetch the latest
      clnum = MAXINT
    return self.t.FetchMemory(clnum, address, llen)

  def fetch_changes_by_clnum(self, clnum, limit):
    ret = []
    if limit == -1:
      limit = 0
    its = self.t.FetchChangesByClnum(clnum, limit)
    for it in its:
      tl = {"address": it.address,
            "data": it.data,
            "clnum": it.clnum,
            "type": chr(self.t.get_type_from_flags(it.flags)),
            "size": it.flags & SIZE_MASK}
      ret.append(tl)
    return ret

