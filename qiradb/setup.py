#!/usr/bin/env python2.7
import os
from version import __version__
from distutils.core import setup, Extension
import distutils.sysconfig

cfg_vars = distutils.sysconfig.get_config_vars()
for key, value in cfg_vars.items():
    if type(value) == str:
        cfg_vars[key] = value.replace("-Wstrict-prototypes", "")

# the c++ extension module
os.environ["CC"] = "g++"
os.environ["CXX"] = "g++"
extension_mod = Extension("qiradb._qiradb", sources=["qiradb/Trace.cpp", "qiradb/_qiradb.cpp"], language="c++")

url="https://github.com/BinaryAnalysisPlatform"
description="QEMU Interactive Runtime Analyser, QIRADB Tracer package."

# specify the package
setup(name='qiradb', version=__version__, url=url, description=description, ext_modules=[extension_mod], packages=['qiradb'])

