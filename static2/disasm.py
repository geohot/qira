
# capstone is a requirement now
from capstone import *

def disasm(raw, address, arch):
  default = {"repr": raw.encode("hex")}
  try:
    if arch == "i386":
      md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == "x86-64":
      md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "thumb":
      md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif arch == "arm":
      md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch == "aarch64":
      md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == "ppc":
      md = Cs(CS_ARCH_PPC, CS_MODE_32)
      #if 64 bit: md.mode = CS_MODE_64
    else:
      raise Exception('arch not in capstone')
    #next: store different data based on type of operand
    #https://github.com/aquynh/capstone/blob/master/bindings/python/test_arm.py
    md.detail = True
    try:
      i = md.disasm(raw, address).next()
    except StopIteration: #not a valid instruction
      return default
    # should only be one instruction
    # may not need to track iset here
    # the repr field is a fallback representation of the instruction
    data = {"mnemonic": i.mnemonic, "op_str": i.op_str,
        "repr": "{}\t{}".format(i.mnemonic,i.op_str)}
    if len(i.regs_read) > 0:
      data["regs_read"] = [i.reg_name(r) for r in i.regs_read]
    if len(i.regs_write) > 0:
      data["regs_write"] = [i.reg_name(r) for r in i.regs_write]
    #groups: is it in arm neon, intel sse, etc
    #if len(i.groups) > 0:
    #  data["groups"] = []
    #  for g in i.groups:
    #    data["groups"].append(g)

    # we aren't ready for more yet
    return data
    #when ready, return data as json rather than static string
  except Exception, e:
    print "capstone disasm failed: {}".format(sys.exc_info()[0]), e
    return default

