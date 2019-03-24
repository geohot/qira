import sys

# only pyximport this
import pyximport
py_importer, pyx_importer = pyximport.install()
from .qiradb import PyTrace
sys.meta_path.remove(pyx_importer)

