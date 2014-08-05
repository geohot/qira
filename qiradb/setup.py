#!/usr/bin/env python2.7
from setuptools import setup, Extension

# should be a symlink to the root
# could also add the git rev to this?
version=open('VERSION').read().strip()

# the c++ extension module
extension_mod = Extension("qiradb._qiradb", ["qiradb/Trace.cpp", "qiradb/_qiradb.cpp"])

# specify the package
setup(name='qiradb', version=version, ext_modules=[extension_mod], packages=['qiradb'])

