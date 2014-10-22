#linear.py
# Makes a linear sweep over the binary to identify function starts,
# then builds basic blocks for each identified function. This approach
# should be superior with ARM, or in cases where the compiler does not
# emit a return instruction at the end of a function (infinite loop, etc.).

import disasm

#this is designed with ARM in mind.
#if we take this approach with other architectures it should be modularized.
def get_function_starts(static):
  function_starts = set()
  entry = static['entry']

  def get_start(section):
    return section[0]

  #get the section that contains the entry
  #if it's always the case that the entry is the beginning of a section,
  #we can just look for it in static['sections'] and be done
  (start,size) = max((x for x in static['sections'] if get_start(x) <= entry),
                     key=get_start)
  end = start+size

  current_address = entry
  while (current_address < end):
    #mem = static.memory(current_address,0x10) #get an instruction
    d = static[current_address]['instruction']
    if d.itype == disasm.ITYPE.call:
      #we want the immediate (the function), not the next instruction
      succ_l = [i for (i,t) in d.succ if (t == disasm.TTYPE.immediate)]
      assert len(succ_l) == 1 #only one target
      successor_f = succ_l[0] #unpack from list
      static[successor_f]['xrefs'].add(current_address)
      static._auto_update_name(successor_f, "sub_{%x}"%(successor_f))
      function_starts.add(successor_f)
    #assume sizeof(instruction) is 16 for ARM
    #we can also get this information from the disasm
    #TODO: add thumb support to disasm, it seems the class refactor broke it
    current_address += 0x10

  print "found function starts",function_starts

  return function_starts
