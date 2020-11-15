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


ifndef TOP
  TOP = $(shell while ! test -e make.rules; do cd ..  ; done; pwd)
  export TOP
endif
include $(TOP)/make.rules


OBJS	= sbrk.o
OBJDIRS = time/time.o
SUBDIRS = $(filter-out ./,$(dir $(OBJDIRS)))


all:	subdirs
	$(MAKE) libc-glue.o

libc-glue.o: $(OBJS) $(OBJDIRS)
	$(LD) $(LDFLAGS) $(OBJS) $(OBJDIRS) -o $@ -r


subdirs :
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir DIRECTORY=$(DIRECTORY)$$dir || exit 1; \
	done

clean:
	$(RM) -f *.a *.o
	@for dir in $(SUBDIRS); do \
		$(CLEAN) ; \
		$(MAKE) -C $$dir DIRECTORY=$(DIRECTORY)$$dir clean; \
	done

include $(TOP)/make.depend
