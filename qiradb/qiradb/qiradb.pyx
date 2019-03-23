# distutils: language = c++

"""
static PyMethodDef Trace_methods[] = {
  { "get_maxclnum", (PyCFunction)get_maxclnum, METH_NOARGS, NULL },
  { "get_minclnum", (PyCFunction)get_minclnum, METH_NOARGS, NULL },
  { "get_pmaps", (PyCFunction)get_pmaps, METH_NOARGS, NULL },
  { "did_update", (PyCFunction)did_update, METH_NOARGS, NULL },
  { "fetch_clnums_by_address_and_type", (PyCFunction)fetch_clnums_by_address_and_type, METH_VARARGS, NULL },
  { "fetch_changes_by_clnum", (PyCFunction)fetch_changes_by_clnum, METH_VARARGS, NULL },
  { "fetch_memory", (PyCFunction)fetch_memory, METH_VARARGS, NULL },
  { "fetch_registers", (PyCFunction)fetch_registers, METH_VARARGS, NULL },
  { NULL, NULL, 0, NULL }
};
"""

from Trace.Trace cimport Trace

cdef class PyTrace:
  cdef Trace t

  def __cinit__(self, filename, trace_index, register_size, register_count, is_big_endian):
    self.t = Trace()
    self.t.ConnectToFileAndStart(filename, trace_index, register_size, register_count, is_big_endian)

  def get_maxclnum(self):
    return self.t.GetMaxClnum()

  def get_minclnum(self):
    return self.t.GetMinClnum()


