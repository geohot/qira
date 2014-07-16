# QIRA would be a better place if these things came from QEMU

import subprocess
from elftools.elf.elffile import ELFFile

def file_binary():
  instructions = {}
  return subprocess.Popen(
    ["file", "-L", "/tmp/qira_binary"],
    stdout = subprocess.PIPE).communicate()[0].strip()

def objdump_binary():
  instructions = {}
  # get the instructions
  # should really get these from QEMU
  objdump_out = subprocess.Popen(
    ["objdump", "-d", "/tmp/qira_binary"],
    stdout = subprocess.PIPE).communicate()[0]
  for line in objdump_out.split("\n"):
    line = line.split("\t")
    if len(line) == 3:
      addr = int(line[0].strip(" :"), 16)
      instructions[addr] = line[2]
      #print hex(addr), line[2]
    else:
      # could get names here too, but maybe useless for now
      pass
  print "objdump parse got",len(instructions),"instructions"
  return instructions

def mem_commit_base_binary(mem):
  # get the memory base
  elf = ELFFile(open("/tmp/qira_binary"))
  for seg in elf.iter_segments():
    try:
      vaddr = seg.header['p_vaddr']
      flags = seg.header['p_flags']
      data = seg.data()
    except:
      continue

    # should we gate the segment on something?
    # i think any data actually in the ELF file is good
    for i in range(0, len(data)):
      mem.commit(0, vaddr+i, ord(data[i]))

