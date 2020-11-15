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

TOP=$(shell pwd)
export TOP
include $(TOP)/make.rules
    
OBJS	=  kernel/kernel.o oflib/oflib.o libc/libc-glue.o app/app.o
.PHONY : subdirs clean depend mrproper

CLIENTLIBS = $(LIBCMNDIR)/libelf.a $(LIBCMNDIR)/libc.a

all:	.depend subdirs
	$(MAKE) client

client : $(OBJS) $(CLIENTLIBS)
	$(LD) $(LDFLAGS) -o $@ -Tclient.lds $(OBJS) $(CLIENTLIBS)
	cp $@ $@.unstripped
	$(STRIP) --strip-unneeded $@

client.dis: client
	$(OBJDUMP) -DSsx client.unstripped > $@

sec-client : subdirs $(OBJS) $(LIBCMNDIR)/libc.a
	$(LD) $(LDFLAGS) -o $@ -Tsec-client.lds $(OBJS) $(LIBCMNDIR)/libc.a

subdirs : 
	@for dir in $(dir $(OBJS)); do \
	  $(MAKE) -C $$dir || exit 1; \
	done

$(LIBCMNDIR)/%.a:
	$(MAKE) -C $(LIBCMNDIR) $(@:$(LIBCMNDIR)/%.a=%)

clean: 
	@for dir in $(dir $(OBJS)); do \
	  $(MAKE) -C $$dir clean; \
	done
	rm -f $(OBJS) client diag netboot sec-client net-diag \
		*.dis client.unstripped fpga-client

mrproper : clean
	$(MAKE) -C app mrproper
	$(MAKE) -C libc mrproper
	$(MAKE) -C kernel mrproper
	$(MAKE) -C oflib mrproper
	find -name .*.bak | xargs rm -rf
	$(RM) .depend

distclean: mrproper

depend .depend:
	$(MAKE) -C app depend
	$(MAKE) -C libc depend
	$(MAKE) -C kernel depend
	$(MAKE) -C oflib depend
	touch .depend
