from qira_log import *

def do_block_analysis(dat):
  # look at addresses
  # if an address can accept control from two addresses, it starts a basic block
  # if an address can give control to two addresses, it ends a basic block
  #   so add those two addresses to the basic block breaker set


  # address = [all that lead into it]
  prev_map = {}
  next_map = {}

  # address

  prev = None
  next_instruction = None

  basic_block_starts = set()

  for (address, data, clnum, flags) in dat:
    if not flags & IS_START:
      continue
    if next_instruction != None and next_instruction != address:
      # anytime we don't run the next instruction in sequence
      # this is a basic block starts
      # print next_instruction, address, data
      basic_block_starts.add(address)

    if address not in prev_map:
      prev_map[address] = set()
    if prev not in next_map:
      next_map[prev] = set()

    prev_map[address].add(prev)
    next_map[prev].add(address)
    prev = address
    next_instruction = address + data

  #print prev_map
  #print next_map

  # accepts control from two addresses
  for a in prev_map:
    if len(prev_map[a]) > 1:
      basic_block_starts.add(a)
  # gives control to two addresses
  for a in next_map:
    if len(next_map[a]) > 1:
      for i in next_map[a]:
        basic_block_starts.add(i)

  #print basic_block_starts

  blocks = []
  cchange = None
  last = None

  for (address, data, clnum, flags) in dat:
    if not flags & IS_START:
      continue
    if cchange == None:
      cchange = (clnum, address)
    if address in basic_block_starts:
      blocks.append({'clstart': cchange[0], 'clend': last[0], 'start': cchange[1], 'end': last[1]})
      cchange = (clnum, address)
    last = (clnum, address)

  blocks.append({'clstart': cchange[0], 'clend': last[0], 'start': cchange[1], 'end': last[1]})
  return blocks


