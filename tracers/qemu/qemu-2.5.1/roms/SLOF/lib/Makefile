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

SUBDIRS = libc libipmi libbootmsg libbases libnvram libelf libhvcall libvirtio \
          libusb libveth libe1k libbcm

all:  subdirs

.PHONY : subdirs $(SUBDIRS) clean distclean


subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKEARG)

# Rules for making clean:
clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean || exit 1; \
	done

distclean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir distclean || exit 1; \
	done
