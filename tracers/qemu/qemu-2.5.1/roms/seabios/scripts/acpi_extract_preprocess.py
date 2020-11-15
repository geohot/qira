#!/usr/bin/python
# Copyright (C) 2011 Red Hat, Inc., Michael S. Tsirkin <mst@redhat.com>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

# Read a preprocessed ASL listing and put each ACPI_EXTRACT
# directive in a comment, to make iasl skip it.
# We also put each directive on a new line, the machinery
# in scripts/acpi_extract.py requires this.

import re
import sys
import fileinput

def die(diag):
    sys.stderr.write("Error: %s\n" % (diag))
    sys.exit(1)

# Note: () around pattern make split return matched string as part of list
psplit = re.compile(r''' (
                          \b # At word boundary
                          ACPI_EXTRACT_\w+ # directive
                          \s+ # some whitespace
                          \w+ # array name
                         )''', re.VERBOSE)

lineno = 0
for line in fileinput.input():
    # line number and debug string to output in case of errors
    lineno = lineno + 1
    debug = "input line %d: %s" % (lineno, line.rstrip())

    s = psplit.split(line)
    # The way split works, each odd item is the matching ACPI_EXTRACT directive.
    # Put each in a comment, and on a line by itself.
    for i in range(len(s)):
        if (i % 2):
            sys.stdout.write("\n/* %s */\n" % s[i])
        else:
            sys.stdout.write(s[i])

