
# returns list of addresses with respect to the qira memory model
# use no dependencies other than bap toil
# make < 100 FFI calls

def fbi(static):
  for (addr, lenn) in static['sections']:
    strr = static.memory(addr, lenn)
  return []

