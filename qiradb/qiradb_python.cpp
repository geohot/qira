#include <Python.h>
#include "qiradb.h"

#if __cplusplus == 201103L
#define FE(x,y) for (auto y = x.begin(); y != x.end(); ++y)
#else
#define FE(x,y) for (typeof(x.begin()) y = x.begin(); y != x.end(); ++y)
#endif


extern "C" {

// do not delete from this vector
static vector<Trace*> traces;

static PyObject *new_trace(PyObject *self, PyObject *args) {
  char *filename;
  int register_size, register_count;
  unsigned int ti;
  if (!PyArg_ParseTuple(args, "Isii", &ti, &filename, &register_size, &register_count)) { return Py_False; }
  Trace *t = new Trace(ti);
  if (!t->ConnectToFileAndStart(filename, register_size, register_count)) { delete t; return Py_False; }
  if (traces.size() <= ti) traces.resize(ti+1);
  traces[ti] = t;
  return Py_True;
}

static PyObject *get_maxclnum(PyObject *self, PyObject *args) {
  unsigned int ti;
  if (!PyArg_ParseTuple(args, "I", &ti) || ti >= traces.size()) { return NULL; }
  Trace *trace = traces[ti]; if (trace == NULL) { return NULL; }

  return Py_BuildValue("I", traces[ti]->GetMaxClnum());
}

static PyObject *did_update(PyObject *self, PyObject *args) {
  unsigned int ti;
  if (!PyArg_ParseTuple(args, "I", &ti) || ti >= traces.size()) { return NULL; }
  Trace *trace = traces[ti]; if (trace == NULL) { return NULL; }

  if (trace->GetDidUpdate()) {
    return Py_True;
  } else {
    return Py_False;
  }

  return Py_BuildValue("I", traces[ti]->GetMaxClnum());
}

static PyObject *fetch_clnums_by_address_and_type(PyObject *self, PyObject *args) { 
  unsigned int ti;
  Address address;
  char type;
  Clnum start_clnum;
  unsigned int limit;
  if (!PyArg_ParseTuple(args, "ILcII", &ti, &address, &type, &start_clnum, &limit) || ti >= traces.size()) { return NULL; }
  Trace *trace = traces[ti]; if (trace == NULL) { return NULL; }
  
  vector<Clnum> ret = trace->FetchClnumsByAddressAndType(address, type, start_clnum, limit);
 
  PyObject *pyret = PyList_New(ret.size());
  int i = 0;
  FE(ret, it) {
    PyList_SetItem(pyret, i++, Py_BuildValue("I", *it));
  }
  return pyret;
}

static PyObject *fetch_changes_by_clnum(PyObject *self, PyObject *args) {
  unsigned int ti;
  Clnum clnum;
  unsigned int limit;
  if (!PyArg_ParseTuple(args, "III", &ti, &clnum, &limit) || ti >= traces.size()) { return NULL; }
  Trace *trace = traces[ti]; if (trace == NULL) { return NULL; }

  vector<struct change> ret = trace->FetchChangesByClnum(clnum, limit);

  PyObject *pyret = PyList_New(ret.size());
  int i = 0;
  FE(ret, it) {
    // copied (address, data, clnum, flags) from qira_log.py, but type instead of flags
    PyObject *iit = PyDict_New();
    PyDict_SetItem(iit, Py_BuildValue("s", "address"), Py_BuildValue("L", it->address));
    PyDict_SetItem(iit, Py_BuildValue("s", "data"), Py_BuildValue("L", it->data));
    PyDict_SetItem(iit, Py_BuildValue("s", "clnum"), Py_BuildValue("I", it->clnum));
    PyDict_SetItem(iit, Py_BuildValue("s", "type"), Py_BuildValue("c", Trace::get_type_from_flags(it->flags)));
    PyDict_SetItem(iit, Py_BuildValue("s", "size"), Py_BuildValue("I", it->flags & SIZE_MASK));
    PyList_SetItem(pyret, i++, iit);
  }
  return pyret;
}

static PyObject *fetch_memory(PyObject *self, PyObject *args) {
  unsigned int ti;
  Clnum clnum;
  Address address;
  int len;
  if (!PyArg_ParseTuple(args, "IILi", &ti, &clnum, &address, &len) || ti >= traces.size()) { return NULL; }
  Trace *trace = traces[ti]; if (trace == NULL) { return NULL; }

  vector<MemoryWithValid> ret = trace->FetchMemory(clnum, address, len);

  PyObject *pyret = PyList_New(ret.size());
  int i = 0;
  FE(ret, it) {
    PyList_SetItem(pyret, i++, Py_BuildValue("I", *it));
  }
  return pyret;
}

static PyObject *fetch_registers(PyObject *self, PyObject *args) {
  unsigned int ti;
  Clnum clnum;
  if (!PyArg_ParseTuple(args, "II", &ti, &clnum) || ti >= traces.size()) { return NULL; }
  Trace *trace = traces[ti]; if (trace == NULL) { return NULL; }

  vector<uint64_t> ret = trace->FetchRegisters(clnum);

  PyObject *pyret = PyList_New(ret.size());
  int i = 0;
  FE(ret, it) {
    PyList_SetItem(pyret, i++, Py_BuildValue("L", *it));
  }
  return pyret;
}


// python stuff follows

static PyMethodDef Methods[] = {
  { "new_trace", new_trace, METH_VARARGS, NULL },
  { "get_maxclnum", get_maxclnum, METH_VARARGS, NULL },
  { "did_update", did_update, METH_VARARGS, NULL },
  { "fetch_clnums_by_address_and_type", fetch_clnums_by_address_and_type, METH_VARARGS, NULL },
  { "fetch_changes_by_clnum", fetch_changes_by_clnum, METH_VARARGS, NULL },
  { "fetch_memory", fetch_memory, METH_VARARGS, NULL },
  { "fetch_registers", fetch_registers, METH_VARARGS, NULL },
  { NULL, NULL, 0, NULL }
};

void initqiradb(void) {
  Py_InitModule("qiradb", Methods);
}

}

