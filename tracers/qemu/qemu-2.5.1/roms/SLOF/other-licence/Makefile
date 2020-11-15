# *****************************************************************************
# * Copyright (c) 2004, 2008 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/

ifndef TOP
  TOP = $(shell while ! test -e make.rules; do cd ..  ; done; pwd)
  export TOP
endif
include $(TOP)/make.rules

SUBDIRS=
ifeq ($(SNK_BIOSEMU_APPS), 1)
SUBDIRS += x86emu
endif
CLEANSUBDIRS = $(SUBDIRS) 


all :
	for subdir in $(SUBDIRS) ; do $(MAKE) -C $${subdir} || exit 1 ; done

# Common targets for all subdirectories:
clean distclean depend:
	for subdir in $(CLEANSUBDIRS) ; do $(MAKE) -C $${subdir} $@ ; done
