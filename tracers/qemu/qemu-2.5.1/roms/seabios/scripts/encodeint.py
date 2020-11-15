#!/usr/bin/env python
# Encode an integer in little endian format in a file.
#
# Copyright (C) 2011  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import sys
import struct

def main():
    filename = sys.argv[1]
    value = int(sys.argv[2], 0)

    outval = struct.pack('<Q', value)
    f = open(filename, 'wb')
    f.write(outval)
    f.close()

if __name__ == '__main__':
    main()
