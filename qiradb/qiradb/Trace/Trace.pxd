from libc.stdint cimport uint32_t
from libcpp cimport bool

cdef extern from "Trace.cpp":
  pass

cdef extern from "Trace.h":
  ctypedef uint32_t Clnum;

  cdef cppclass Trace:
    Trace()
    bool ConnectToFileAndStart(char *filename, unsigned int trace_index, int register_size, int register_count, bool is_big_endian)
    Clnum GetMaxClnum()
    Clnum GetMinClnum()

