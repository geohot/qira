from elftools.elf.elffile import ELFFile
from glob import glob

def get_functions(dwarfinfo):
    function_starts = set()
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag == "DW_TAG_subprogram":
                if 'DW_AT_low_pc' in die.attributes:
                    function_starts.add(die.attributes['DW_AT_low_pc'].raw_value)
    return function_starts

path = "/vagrant/qira/tests_new/binary-autogen/*"
for fn in glob(path):
    elf = ELFFile(open(fn))

    if elf.has_dwarf_info():
        dwarfinfo = elf.get_dwarf_info()
        print fn,get_functions(dwarfinfo)
    else:
        print "No dwarf info for {}.".format(fn)

#todo: use static backends

