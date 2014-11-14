from model import Block, Function
import re

def analyze_functions(static):
  rc = static.r2core
  flags = rc.cmd_json("fj")
  for flag in flags:
      if "loc_" in flag['name']:
          static._auto_update_name(flag['offset'],flag['name'])

  functions = rc.cmd("afl~!sym.imp[0]").split('\n')
  for addr_s in functions:
    try:
      addr = int(addr_s[2:],16)
      make_function_at(static, addr)
    except:
      pass

def make_function_at(static, addr):
  if static[addr]['function'] != None:
    # already function
    return
  rc = static.r2core
  rc.cmd("af @ %d" % (addr,))
  this_function = Function(addr)
  static['functions'].add(this_function)
      
  info = rc.cmd_json("afj %d" % (addr,))[0]
  callrefs = info['callrefs'] 
  for ref in callrefs:
    if ref["type"] == "J":
      static[ref['addr']]['crefs'].add(addr)
    if ref["type"] == "C":
      static[ref['addr']]['xrefs'].add(addr)

  function_details = rc.cmd_json("pdfj @ %d" % addr)
  if function_details['addr'] == addr:
    for opcode in function_details['ops']:
      static[opcode['offset']]['function'] = this_function 
      i = static[opcode['offset']]['instruction']

  addr_re = re.compile(r'\| (0x[a-f0-9]+) ')
  blocks = rc.cmd_json("agj %d" % addr)[0]['blocks']
  for block in blocks:
    this_block = Block(block['offset'])
    this_function.add_block(this_block)
    addresses = addr_re.findall(block['code']) 
    for address in addresses:
      address = int(address[2:],16)
      this_block.add(address)
      static[address]['block'] = this_block
    static['blocks'].add(this_block)

