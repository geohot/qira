#include "qiradb.h"

static PyMethodDef Methods[] = {
  { "test", qiradb_test, METH_VARARGS, "Say hello" },
  { NULL, NULL, 0, NULL }
};

DL_EXPORT(void) initqiradb(void) {
  Py_InitModule("qiradb", Methods);
}

PyObject *qiradb_test(PyObject *self, PyObject *args) {
  return Py_BuildValue("i", 69);
}

