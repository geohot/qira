from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

def load_binary(static, path):
  elf = ELFFile(open(path))

  # hacks say ELF loads at 0x8048000
  dat = open(path).read()
  static.add_memory_chunk(0x8048000, dat)

  ncount = 0
  for section in elf.iter_sections():
    if isinstance(section, RelocationSection):
      symtable = elf.get_section(section['sh_link'])
      for rel in section.iter_relocations():
        symbol = symtable.get_symbol(rel['r_info_sym'])
        #print rel, symbol.name
        if rel['r_offset'] != 0 and symbol.name != "":
          static[rel['r_offset']]['name'] = "__"+symbol.name
          ncount += 1

    if isinstance(section, SymbolTableSection):
      for nsym, symbol in enumerate(section.iter_symbols()):
        if symbol['st_value'] != 0 and symbol.name != "" and symbol['st_info']['type'] == "STT_FUNC":
          #print symbol['st_value'], symbol.name
          static[symbol['st_value']]['name'] = symbol.name
          ncount += 1
  print "** found %d names" % ncount

