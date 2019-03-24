try:
  import Queue
except ImportError:
  import queue as Queue
from model import Function, Block, DESTTYPE
import byteweight
import time

def analyze_functions(static):
  make_function_at(static, static['entry'])
  main = static.get_address_by_name("main")
  if main != None:
    make_function_at(static, main)
  bw_functions = byteweight.fsi(static)
  for f in bw_functions:
    make_function_at(static, f)

# things to actually drive the static analyzer
# runs the recursive descent parser at address
# how to deal with block groupings?
def make_function_at(static, address, recurse = True):
  if static[address]['function'] != None:
    # already function
    return
  start = time.time()
  block_starts = set([address])
  function_starts = set()
  this_function = Function(address)
  static['functions'].add(this_function)

  def disassemble(address):
    raw = static.memory(address, 0x10)
    d = static[address]['instruction']
    static[address]['function'] = this_function
    for (c,flag) in d.dests():
      if flag == DESTTYPE.call:
        static._auto_update_name(c,"sub_%x"%(c))
        function_starts.add(c)
        #print "%s %x is in %x xrefs" % (d,address, c)
        static[c]['xrefs'].add(address)
        # add this to the potential function boundary starts
        continue
      if c != address + d.size():
        #print "%s %x is in %x crefs" % (d,address, c)
        static[c]['crefs'].add(address)
        static._auto_update_name(c,"loc_%x"%(c))
        block_starts.add(c)

      #if we come after a jump and are an implicit xref, we are the start
      #of a new block
      elif d.is_jump() and not d.is_call():
        static._auto_update_name(c,"loc_%x"%(c))
        block_starts.add(c)
    return d.dests()

  # recursive descent pass
  pending = Queue.Queue()
  done = set()
  pending.put(address)
  while not pending.empty():
    dests = disassemble(pending.get())
    for (d,flag) in dests:
      if flag == DESTTYPE.call:
        #this will get handled in the function pass
        continue
      if d not in done:
        pending.put(d)
        done.add(d)
    if (time.time() - start) > 0.01:
      time.sleep(0.01)
      start = time.time()

  #print map(hex, done)

  # block finding pass
  for b in block_starts:
    this_block = Block(b)
    this_function.add_block(this_block)
    address = b
    i = static[address]['instruction']
    while not i.is_ending() and i.size() != 0:
      if address + i.size() in block_starts:
        break
      address += i.size()
      i = static[address]['instruction']
      this_block.add(address)
      static[address]['block'] = this_block
      if (time.time() - start) > 0.01:
        time.sleep(0.01)
        start = time.time()
    static['blocks'].add(this_block)

   # find more functions
  if recurse:
    for f in function_starts:
      if static[f]['function'] == None:
        make_function_at(static, f)
