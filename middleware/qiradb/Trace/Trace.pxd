# distutils: language = c++

from libc.stdint cimport uint32_t, uint64_t, uint16_t
from libcpp cimport bool
from libcpp.map cimport map
from libcpp.vector cimport vector

cdef extern from "Trace.cpp":
  pass

cdef extern from "Trace.h":
  ctypedef uint32_t Clnum;
  ctypedef uint64_t Address;
  ctypedef uint16_t MemoryWithValid;

  cdef struct change:
    Address address
    uint64_t data
    Clnum clnum
    uint32_t flags

  cdef cppclass Trace:
    Trace(bool quiet)
    bool ConnectToFileAndStart(char *filename, unsigned int trace_index, int register_size, int register_count, bool is_big_endian)
    Clnum GetMaxClnum()
    Clnum GetMinClnum()
    bool GetDidUpdate()

    map[Address, char] GetPages()
    vector[Clnum] FetchClnumsByAddressAndType(Address, char, Clnum, Clnum, unsigned int)
    vector[uint64_t] FetchRegisters(Clnum clnum)
    vector[MemoryWithValid] FetchMemory(Clnum clnum, Address address, int len)
    vector[change] FetchChangesByClnum(Clnum clnum, unsigned int limit)

    char get_type_from_flags(uint32_t flags)

