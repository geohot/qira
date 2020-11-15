# *****************************************************************************
# * Copyright (c) 2004, 2011 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/

BOARD_TARGETS = tools_build romfs_build clients_build stage1 subdirs

SUBDIRS = slof

COMMON_LIBS = libc libbootmsg libbases libnvram libelf libhvcall libvirtio libusb \
              libveth libe1k

all: $(BOARD_TARGETS)
	$(MAKE) boot_rom.bin

.PHONY : subdirs $(SUBDIRS) clean distclean

include config
include Makefile.dirs
include $(TOPCMNDIR)/make.rules
include $(TOPCMNDIR)/Makefile.gen

subdirs: $(SUBDIRS)

$(SUBDIRS): common-libs
	@echo " ====== Building $@ ======"
	$(MAKE) -C $@ $(MAKEARG) RELEASE=-DRELEASE=\"\\\"$(RELEASE)\\\"\"

stage1:	common-libs
	@echo " ====== Building llfw ======"
	$(MAKE) -C llfw RELEASE=-DRELEASE=\"\\\"$(RELEASE)\\\"\"

clean_here:
	rm -f ../slof/OF.ffs
	rm -f ../boot_rom.bin

clean:	clean_here clean_gen
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean || exit 1; \
	done
	rm -f ../boot_rom.bin 
	@$(MAKE) -C llfw clean

distclean:	clean_here distclean_gen
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir distclean || exit 1; \
	done
	rm -f ../boot_rom.bin 
	$(MAKE) -C llfw clean

.driver_dirs:
	@rm -rf ../driver-$(RELEASE)
	@mkdir -p ../driver-$(RELEASE)

.tar_gz:	.driver_dirs
	@mv ../boot_rom.bin ../driver-$(RELEASE)/$(RELEASE)-slof.bin
	@cp ../VERSION ../driver-$(RELEASE)
	@cp changes.txt ../driver-$(RELEASE)
	@cd ../driver-$(RELEASE) && md5sum * > md5sum.txt
	@chmod 644 ../driver-$(RELEASE)/*
	@mv ../driver-$(RELEASE) ../driver-$(RELEASE)-`date +%Y-%h%d`
	@tar czf ../driver-$(RELEASE)-`date +%Y-%h%d`.tar.gz \
		../driver-$(RELEASE)-`date +%Y-%h%d` > /dev/null  2>&1
	@rm -rf ../driver-$(RELEASE)-`date +%Y-%h%d`

driver:		driver_prep clean .tar_gz
