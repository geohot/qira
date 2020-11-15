#!/usr/bin/env python

# This script is useful for taking the output of memdump() and
# converting it back into binary output.  This can be useful, for
# example, when one wants to push that data into other tools like
# objdump or hexdump.
#
# (C) Copyright 2010 Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import sys
import struct

def unhex(str):
    return int(str, 16)

def parseMem(filehdl):
    mem = []
    for line in filehdl:
        parts = line.split(':')
        if len(parts) < 2:
            continue
        try:
            vaddr = unhex(parts[0])
            parts = parts[1].split()
            mem.extend([unhex(v) for v in parts])
        except ValueError:
            continue
    return mem

def printUsage():
    sys.stderr.write("Usage:\n %s <file | ->\n"
                     % (sys.argv[0],))
    sys.exit(1)

def main():
    if len(sys.argv) != 2:
        printUsage()
    filename = sys.argv[1]
    if filename == '-':
        filehdl = sys.stdin
    else:
        filehdl = open(filename, 'r')
    mem = parseMem(filehdl)
    for i in mem:
        if (sys.version_info > (3, 0)):
            sys.stdout.buffer.write(struct.pack("<I", i))
        else:
            sys.stdout.write(struct.pack("<I", i))

if __name__ == '__main__':
    main()
