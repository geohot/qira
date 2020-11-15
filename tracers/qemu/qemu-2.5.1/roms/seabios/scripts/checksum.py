#!/usr/bin/env python
# Script to report the checksum of a file.
#
# Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import sys

def main():
    data = sys.stdin.read()
    ords = map(ord, data)
    print("sum=%x\n" % sum(ords))

if __name__ == '__main__':
    main()
