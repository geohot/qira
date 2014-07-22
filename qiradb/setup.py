from distutils.core import setup, Extension

# the c++ extension module
extension_mod = Extension("qiradb", ["qiradb.cpp", "qiradb_python.cpp"])

setup(name = "qiradb", ext_modules=[extension_mod])

