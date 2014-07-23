#include <Python.h>
#include <structmember.h>
#include "qiradb.h"

#if __cplusplus == 201103L
#define FE(x,y) for (auto y = x.begin(); y != x.end(); ++y)
#else
#define FE(x,y) for (typeof(x.begin()) y = x.begin(); y != x.end(); ++y)
#endif

extern "C" {

typedef struct {
  PyObject_HEAD
  Trace *t;
} PyTrace;

static int Trace_init(PyTrace *self, PyObject *args, PyObject *kwds) {
  char *filename;
  int register_size, register_count;
  unsigned int ti;
  if (!PyArg_ParseTuple(args, "sIii", &filename, &ti, &register_size, &register_count)) { return -1; }
  Trace *t = new Trace(ti);
  if (!t->ConnectToFileAndStart(filename, register_size, register_count)) { delete t; return -1; }
  self->t = t;
  return 0;
}

static void Trace_dealloc(PyTrace *self) {
  if (self->t != NULL) { delete self->t; }
  self->ob_type->tp_free((PyObject*)self);
}

static PyObject *get_maxclnum(PyTrace *self) {
  if (self->t == NULL) { return NULL; }
  return Py_BuildValue("I", self->t->GetMaxClnum());
}

static PyObject *get_minclnum(PyTrace *self) {
  if (self->t == NULL) { return NULL; }
  return Py_BuildValue("I", self->t->GetMinClnum());
}

static PyObject *did_update(PyTrace *self) {
  if (self->t == NULL) { return NULL; }
  if (self->t->GetDidUpdate()) {
    Py_INCREF(Py_True);
    return Py_True;
  } else {
    Py_INCREF(Py_False);
    return Py_False;
  }
}

static PyObject *fetch_clnums_by_address_and_type(PyTrace *self, PyObject *args) { 
  Address address;
  char type;
  Clnum start_clnum;
  unsigned int limit;
  if (!PyArg_ParseTuple(args, "LcII", &address, &type, &start_clnum, &limit)) { return NULL; }
  if (self->t == NULL) { return NULL; }
  
  vector<Clnum> ret = self->t->FetchClnumsByAddressAndType(address, type, start_clnum, limit);
 
  PyObject *pyret = PyList_New(ret.size());
  int i = 0;
  FE(ret, it) {
    PyList_SetItem(pyret, i++, Py_BuildValue("I", *it));
  }
  return pyret;
}

static PyObject *fetch_changes_by_clnum(PyTrace *self, PyObject *args) {
  Clnum clnum;
  unsigned int limit;
  if (!PyArg_ParseTuple(args, "II", &clnum, &limit)) { return NULL; }
  if (self->t == NULL) { return NULL; }

  vector<struct change> ret = self->t->FetchChangesByClnum(clnum, limit);

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

static PyObject *fetch_memory(PyTrace *self, PyObject *args) {
  Clnum clnum;
  Address address;
  int len;
  if (!PyArg_ParseTuple(args, "ILi", &clnum, &address, &len)) { return NULL; }
  if (self->t == NULL) { return NULL; }

  vector<MemoryWithValid> ret = self->t->FetchMemory(clnum, address, len);

  PyObject *pyret = PyList_New(ret.size());
  int i = 0;
  FE(ret, it) {
    PyList_SetItem(pyret, i++, Py_BuildValue("I", *it));
  }

  return pyret;
}

static PyObject *fetch_registers(PyTrace *self, PyObject *args) {
  Clnum clnum;
  if (!PyArg_ParseTuple(args, "I", &clnum)) { return NULL; }
  if (self->t == NULL) { return NULL; }

  vector<uint64_t> ret = self->t->FetchRegisters(clnum);

  PyObject *pyret = PyList_New(ret.size());
  int i = 0;
  FE(ret, it) {
    PyList_SetItem(pyret, i++, Py_BuildValue("L", *it));
  }
  return pyret;
}

static PyObject *get_pmaps(PyTrace *self, PyObject *args) {
  if (self->t == NULL) { return NULL; }
  set<Address> ip = self->t->GetInstructionPages();
  set<Address> dp = self->t->GetDataPages();
  PyObject *iit = PyDict_New();
  // eww these strings are long
  FE(dp, it) {
    PyDict_SetItem(iit, Py_BuildValue("L", *it), Py_BuildValue("s", "memory"));
  }
  FE(ip, it) {
    PyDict_SetItem(iit, Py_BuildValue("L", *it), Py_BuildValue("s", "instruction"));
  }
  return iit;
}


// python stuff follows

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

static PyMethodDef Methods[] = { {NULL} };

static PyTypeObject qiradb_TraceType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "qiradb_Trace",            /*tp_name*/
    sizeof(PyTrace),           /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)Trace_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
    "Trace object",            /* tp_doc */
    0,                   /* tp_traverse */
    0,                   /* tp_clear */
    0,                   /* tp_richcompare */
    0,                   /* tp_weaklistoffset */
    0,                   /* tp_iter */
    0,                   /* tp_iternext */
    Trace_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Trace_init,      /* tp_init */
};

void initqiradb(void) {
  PyObject* m;
  qiradb_TraceType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&qiradb_TraceType) < 0) return;
  m = Py_InitModule("qiradb", Methods);
  if (m == NULL) return;
  Py_INCREF(&qiradb_TraceType);
  PyModule_AddObject(m, "Trace", (PyObject *)&qiradb_TraceType);
}

}

