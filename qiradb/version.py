#!/usr/bin/env python2.7
import os
import subprocess

# should be a symlink to the root
# could also add the git rev to this?
version_file = open(os.path.join('.', 'VERSION'))
version_number = version_file.read().strip()

__version__ = version_number
