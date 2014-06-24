from qira_log import *

def do_function_analysis(dat):
  next_instruction = None

  fxn_stack = []
  cancel_stack = []
  cl_stack = []

  fxn = []

  for (address, data, clnum, flags) in dat:
    if not flags & IS_START:
      continue
    if address in cancel_stack:
      # reran this address, this isn't return
      idx = cancel_stack.index(address)
      fxn_stack = fxn_stack[0:idx]
      cancel_stack = cancel_stack[0:idx]
      cl_stack = cl_stack[0:idx]
      #print map(hex, fxn_stack), clnum, "cancel"
    if address in fxn_stack:
      idx = fxn_stack.index(address)
      fxn.append((cl_stack[idx],(clnum-1)))
      fxn_stack = fxn_stack[0:idx]
      cancel_stack = cancel_stack[0:idx]
      cl_stack = cl_stack[0:idx]
      #print map(hex, fxn_stack), clnum, "return"
    elif next_instruction != None and next_instruction != address:
      fxn_stack.append(next_instruction)
      cancel_stack.append(last_instruction)
      cl_stack.append(clnum)
      #print map(hex, fxn_stack), clnum
    next_instruction = address + data
    last_instruction = address
  return fxn


def get_depth(fxns, clnum):
  d = 0
  for f in fxns:
    if clnum >= f[0] and clnum <= f[1]:
      d += 1
  return d

if __name__ == "__main__":
  dat = read_log("/tmp/qira_log")
  print do_function_analysis(dat)

