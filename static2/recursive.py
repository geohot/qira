import Queue
import disasm

class Function:
  def __init__(self, start):
    self.start = start
    self.blocks = set()

  def __repr__(self):
    return hex(self.start) + " " + str(self.blocks)

  def add_block(self, block):
    self.blocks.add(block)

class Block:
  def __init__(self, start):
    self.__start__ = start
    self.addresses = set([start])

  def __repr__(self):
    return hex(self.start())+"-"+hex(self.end())

  def start(self):
    return self.__start__

  def end(self):
    return max(self.addresses)

  def add(self, address):
    self.addresses.add(address)

# things to actually drive the static analyzer
# runs the recursive descent parser at address
# how to deal with block groupings?
def make_function_at(self, address, recurse = True):
  if self['arch'] != "i386":
    print "*** static only works with x86, someone should fix it"
    return
  block_starts = set([address])
  function_starts = set()
  this_function = Function(address)
  self['functions'].add(this_function)

  def disassemble(address):
    raw = self.memory(address, 0x10)
    d = self[address]['instruction']
    self[address]['function'] = this_function
    for (c,flag) in d.dests():
      if flag == disasm.DESTTYPE.call:
        self._auto_update_name(c,"sub_%x"%(c))
        function_starts.add(c)
        self[c]['xrefs'].add(address)
        # add this to the potential function boundary starts
        continue
      if c != address + d.size():
        self[c]['crefs'].add(address)
        self._auto_update_name(c,"loc_%x"%(c))
        block_starts.add(c)

      #if we come after a jump and are an implicit xref, we are the start
      #of a new block
      elif d.is_jump():
        self._auto_update_name(c,"loc_%x"%(c))
        block_starts.add(c)
    return d.dests()

  # recursive descent pass
  pending = Queue.Queue()
  done = set()
  pending.put(address)
  while not pending.empty():
    dests = disassemble(pending.get())
    for (d,flag) in dests:
      if flag == disasm.DESTTYPE.call:
        #this will get handled in the function pass
        continue
      if d not in done:
        pending.put(d)
        done.add(d)

  #print map(hex, done)

  # block finding pass
  for b in block_starts:
    this_block = Block(b)
    this_function.add_block(this_block)
    address = b
    i = self[address]['instruction']
    while not i.is_ending() and i.size() != 0:
      if address + i.size() in block_starts:
        break
      address += i.size()
      i = self[address]['instruction']
      this_block.add(address)
      self[address]['block'] = this_block
    self['blocks'].add(this_block)

   # find more functions
  for f in function_starts:
    if self[f]['function'] == None:
      make_function_at(self, f)

