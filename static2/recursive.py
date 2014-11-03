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
  #if self['arch'] != "i386" and self['arch'] != "x86-64":
  #  print "*** static only works with x86(_64), someone should fix it"
  #  return
  if address is None:
    return
  block_starts = set([address])
  function_starts = set()
  this_function = Function(address)
  self['functions'].add(this_function)

  def disassemble(address):
    d = self[address]['instruction']
    self[address]['function'] = this_function
    for (c,flag) in d.dests():
      if d.itype == disasm.ITYPE.call:
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
      #ned: not sure if is_cjump goes here but cjumps used to
      #be part of is_jump() so this is the same behavior
      elif d.is_jump() or d.is_cjump():
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
      if flag == disasm.TTYPE.immediate:
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

#this removes the recursive descent pass and makes basic blocks
#this should be in linear.py, but it relies on the Function and Block
#classes - maybe a refactor is necessary
def make_functions_from_starts(static, function_starts):
  # we don't have to sort function_starts because this loop breaks when we
  # reach another function and we are only building basic blocks/updating
  # the interface.
  for address in function_starts:
    this_function = Function(address)
    static['functions'].add(this_function)

    this_block = Block(address)
    this_function.add_block(this_block)
    block_starts = set([address])

    i = static[address]['instruction']
    while not i.is_ending() and i.size() != 0:
      this_block.add(address)
      static[address]['block'] = this_block
      static[address]['function'] = this_function

      if i.is_cjump():
        for (succ_address, target_type) in i.dests():
          if target_type != disasm.TTYPE.seq:
            static[succ_address]['crefs'].add(address)
            static._auto_update_name(succ_address,"loc_%x"%(succ_address))
            block_starts.add(succ_address)
          #do we do anything with the sequential target?
          #is the sequential target a new basic block?
      elif i.is_jump():
        (succ_address,target_type) = list(i.dests())[0] #only one destination
        assert target_type == disasm.TTYPE.immediate
        static._auto_update_name(succ_address,"loc_%x"%(succ_address))
        block_starts.add(succ_address)

      address += i.size()

      if address in function_starts:
        break #done with this function

      if address in block_starts:
        this_block = Block(address)
        this_function.add_block(this_block)
        #static['blocks'].add(this_block)

      i = static[address]['instruction']
