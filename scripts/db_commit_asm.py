from pymongo import MongoClient
from elftools.elf.elffile import ELFFile
import sys
db = MongoClient('localhost', 3001).meteor

ds = []

sdict = {}
cdict = {}

elf = ELFFile(open(sys.argv[1]))
for section in elf.iter_sections():
  try:
    for symbol in section.iter_symbols():
      if len(symbol.name) > 0:
        sdict[symbol['st_value']] = symbol.name
  except:
    pass

if elf.has_dwarf_info() and len(sys.argv) > 2:
  src = open(sys.argv[2]).read().split("\n")
  di = elf.get_dwarf_info()
  for CU in di.iter_CUs():
    for DIE in CU.iter_DIEs():
      #print DIE
      if DIE.tag == 'DW_TAG_subprogram':
        try:
          lowpc = DIE.attributes['DW_AT_low_pc'].value
          highpc = DIE.attributes['DW_AT_high_pc'].value
          fil = DIE.attributes['DW_AT_decl_file']
          line = DIE.attributes['DW_AT_decl_line'].value
        except:
          pass
        print lowpc, highpc, fil, line, src[line]
        cdict[lowpc] = src[line]

dat = open("/tmp/qira_disasm").read().split("\n")
for d in dat:
  if ":  " in d:
    (addr, inst) = d.split(":  ")
    addr = int(addr, 16)
    #print addr, inst
    d = {'address': addr, 'instruction': inst}
    if addr in sdict:
      d['name'] = sdict[addr]
    if addr in cdict:
      print hex(addr)
      d['comment'] = cdict[addr]
    ds.append(d)


# DWARF data will go here too
coll = db.program
print "doing db insert"
coll.drop()
coll.insert(ds)
print "db insert done, building indexes"
coll.ensure_index("address")
print "indexes built"


