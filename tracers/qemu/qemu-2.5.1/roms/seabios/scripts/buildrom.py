#!/usr/bin/env python
# Fill in checksum/size of an option rom, and pad it to proper length.
#
# Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import sys, struct

from python23compat import as_bytes

def alignpos(pos, alignbytes):
    mask = alignbytes - 1
    return (pos + mask) & ~mask

def checksum(data):
    if (sys.version_info > (3, 0)):
        cksum = sum(data)
    else:
        cksum = sum(map(ord, data))
    return struct.pack('<B', (0x100 - cksum) & 0xff)

def main():
    inname = sys.argv[1]
    outname = sys.argv[2]

    # Read data in
    f = open(inname, 'rb')
    data = f.read()
    f.close()
    count = len(data)

    # Pad to a 512 byte boundary
    data += as_bytes("\0") * (alignpos(count, 512) - count)
    count = len(data)

    # Check if a pci header is present
    pcidata = ord(data[24:25]) + (ord(data[25:26]) << 8)
    if pcidata != 0:
        blocks = struct.pack('<H', int(count/512))
        data = data[:pcidata + 16] + blocks + data[pcidata + 18:]

    # Fill in size field; clear checksum field
    blocks = struct.pack('<B', int(count/512))
    data = data[:2] + blocks + data[3:6] + as_bytes("\0") + data[7:]

    # Checksum rom
    data = data[:6] + checksum(data) + data[7:]

    # Write new rom
    f = open(outname, 'wb')
    f.write(data)
    f.close()

if __name__ == '__main__':
    main()
