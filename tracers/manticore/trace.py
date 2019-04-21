#!/usr/bin/env python3
import os
import sys
from manticore.native import Manticore


if __name__ == '__main__':
  if len(sys.argv) < 2:
    sys.stderr.write(f"Usage: {sys.argv[0]} [binary]\n")
    sys.exit(2)

  Manticore.verbosity(2)
  m = Manticore.linux(sys.argv[1], [], envp={"LD_LIBRARY_PATH":os.path.dirname(os.path.realpath(__file__))+"/libs"})

  """
  @m.hook(None)
  def explore(state):
    ins = state.cpu.instruction
    print(hex(ins.address), ins.mnemonic, ins.op_str)
    #print(hex(state.cpu.RIP), state.cpu.instruction.mnemonic)
    with m.locked_context() as context:
      context['count'] += 1
  """

  m.run(procs=1)

