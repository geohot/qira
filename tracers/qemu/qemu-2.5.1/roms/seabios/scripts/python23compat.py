# Helper code for compatibility of the code with both Python 2 and Python 3
#
# Copyright (C) 2014 Johannes Krampf <johannes.krampf@googlemail.com>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import sys

if (sys.version_info > (3, 0)):
    def as_bytes(str):
        return bytes(str, "ASCII")
else:
    def as_bytes(str):
        return str
