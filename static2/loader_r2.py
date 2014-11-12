def get_arch(proc, bits):
  if proc == "x86" and bits == 64:
    return 'x86-64'
  if proc == "x86" and bits == 32:
    return 'i386'
  else:
    return proc

def load_binary(static):
  rc = static.r2core 
  info = rc.cmd_json("iaj")
  relocs = rc.cmd_json("irj")

  static['arch'] = get_arch(info['info']['arch'], info['info']['bits'])
  static['entry'] = info['entries'][0]

  ncount = 0
  for section in info['sections']:
    addr = section['addr']
    slen = section['size']
    name = str(section['name'])
    if addr != 0 and slen > 0 and not name.startswith("phdr") and not name.startswith("ehdr"):
      chunk = rc.cmd("p8 %d @ %s" % (slen, addr,)).rstrip()
      static.add_memory_chunk(addr, chunk.decode('hex'))

  for symbol in info['symbols']:
      if symbol['addr'] != 0 and symbol['name'] != "":
          static[symbol['addr']]['name'] = symbol['name']
          ncount += 1

  for reloc in relocs:
      if reloc['vaddr'] != 0 and reloc['name'] != "" and reloc['name'] is not None:
          static[reloc['vaddr']]['name'] = reloc['name']
          ncount += 1

  print "** found %d names" % ncount

