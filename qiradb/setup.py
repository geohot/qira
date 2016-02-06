#!/usr/bin/env python2.7
from version import __version__
from setuptools import setup, Extension, Command

# the c++ extension module
extension_mod = Extension("qiradb._qiradb", sources=["qiradb/Trace.cpp", "qiradb/_qiradb.cpp"], language="c++")

url="https://github.com/BinaryAnalysisPlatform"
description="QEMU Interactive Runtime Analyser, QIRADB Tracer package."

# specify the package
setup(name='qiradb', version=__version__, url=url, description=description, ext_modules=[extension_mod], packages=['qiradb'])

