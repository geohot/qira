#!/usr/bin/env python
# Script to check a bios image and report info on it.
#
# Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import sys, struct
import layoutrom, buildrom

from python23compat import as_bytes

def subst(data, offset, new):
    return data[:offset] + new + data[offset + len(new):]

def checksum(data, start, size, csum):
    sumbyte = buildrom.checksum(data[start:start+size])
    return subst(data, start+csum, sumbyte)

def main():
    # Get args
    objinfo, finalsize, rawfile, outfile = sys.argv[1:]

    # Read in symbols
    objinfofile = open(objinfo, 'r')
    symbols = layoutrom.parseObjDump(objinfofile, 'in')[1]

    # Read in raw file
    f = open(rawfile, 'rb')
    rawdata = f.read()
    f.close()
    datasize = len(rawdata)
    finalsize = int(finalsize) * 1024
    if finalsize == 0:
        finalsize = 64*1024
        if datasize > 64*1024:
            finalsize = 128*1024
            if datasize > 128*1024:
                finalsize = 256*1024
    if datasize > finalsize:
        print("Error!  ROM doesn't fit (%d > %d)" % (datasize, finalsize))
        print("   You have to either increate the size (CONFIG_ROM_SIZE)")
        print("   or turn off some features (such as hardware support not")
        print("   needed) to make it fit.  Trying a more recent gcc version")
        print("   might work too.")
        sys.exit(1)

    # Sanity checks
    start = symbols['code32flat_start'].offset
    end = symbols['code32flat_end'].offset
    expend = layoutrom.BUILD_BIOS_ADDR + layoutrom.BUILD_BIOS_SIZE
    if end != expend:
        print("Error!  Code does not end at 0x%x (got 0x%x)" % (
            expend, end))
        sys.exit(1)
    if datasize > finalsize:
        print("Error!  Code is too big (0x%x vs 0x%x)" % (
            datasize, finalsize))
        sys.exit(1)
    expdatasize = end - start
    if datasize != expdatasize:
        print("Error!  Unknown extra data (0x%x vs 0x%x)" % (
            datasize, expdatasize))
        sys.exit(1)

    # Fix up CSM Compatibility16 table
    if 'csm_compat_table' in symbols and 'entry_csm' in symbols:
        # Field offsets within EFI_COMPATIBILITY16_TABLE
        ENTRY_FIELD_OFS = 14 # Compatibility16CallOffset (UINT16)
        SIZE_FIELD_OFS = 5   # TableLength (UINT8)
        CSUM_FIELD_OFS = 4   # TableChecksum (UINT8)

        tableofs = symbols['csm_compat_table'].offset - symbols['code32flat_start'].offset
        entry_addr = symbols['entry_csm'].offset - layoutrom.BUILD_BIOS_ADDR
        entry_addr = struct.pack('<H', entry_addr)
        rawdata = subst(rawdata, tableofs+ENTRY_FIELD_OFS, entry_addr)

        tsfield = tableofs+SIZE_FIELD_OFS
        tablesize = ord(rawdata[tsfield:tsfield+1])
        rawdata = checksum(rawdata, tableofs, tablesize, CSUM_FIELD_OFS)

    # Print statistics
    runtimesize = end - symbols['code32init_end'].offset
    print("Total size: %d  Fixed: %d  Free: %d (used %.1f%% of %dKiB rom)" % (
        datasize, runtimesize, finalsize - datasize
        , (datasize / float(finalsize)) * 100.0
        , int(finalsize / 1024)))

    # Write final file
    f = open(outfile, 'wb')
    f.write((as_bytes("\0") * (finalsize - datasize)) + rawdata)
    f.close()

if __name__ == '__main__':
    main()
