#radare2 must be installed.. do we want this in install.sh or travis ci test.sh?

import sys
sys.path.insert(0, '../')
sys.path.insert(0, '../../middleware')

from static2 import *
import os
import subprocess
import argparse

from elftools.elf.elffile import ELFFile
from glob import glob

TEST_PATH = "/vagrant/qira/tests_new/binary-autogen/*"
#ENGINES = ["r2","builtin"]
ENGINES = ["builtin"]

def get_functions(dwarfinfo):
    function_starts = set()
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_subprogram":
                if 'DW_AT_low_pc' in die.attributes:
                    function_starts.add(die.attributes['DW_AT_low_pc'].raw_value)
    return function_starts

if __name__ == "__main__":
    for fn in glob(TEST_PATH):
        elf = ELFFile(open(fn))

        if not elf.has_dwarf_info():
            print "No dwarf info for {}.".format(fn)
            continue

        dwarfinfo = elf.get_dwarf_info()
        dwarf_functions = get_functions(dwarfinfo)

        engine_functions = {}
        for engine in ENGINES:
            this_engine = Static(fn, debug=True, static_engine=engine)
            this_engine.process()
            engine_functions[engine] = {x.start for x in this_engine['functions']}

        for engine,functions in engine_functions.iteritems():
            print "For file {}, {} missed these functions: {}.".format(fn, engine, ", ".join(str(x) for x in dwarf_functions-functions))

#todo: use static backends

