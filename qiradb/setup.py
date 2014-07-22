from distutils.core import setup, Extension

"""
import os
os.environ["CC"] = "clang"
os.environ["CXX"] = "clang"
extension_mod = Extension("qiradb", ["qiradb.cpp", "qiradb_python.cpp"], extra_compile_args=['-std=c++11'])

"""
# the c++ extension module
extension_mod = Extension("qiradb", ["qiradb.cpp", "qiradb_python.cpp"])

setup(name = "qiradb", ext_modules=[extension_mod])

