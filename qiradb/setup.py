from setuptools import setup, Extension

# the c++ extension module
extension_mod = Extension("qiradb", ["src/qiradb.cpp", "src/qiradb_python.cpp"])

setup(name = "qiradb", version='0.6', ext_modules=[extension_mod])

