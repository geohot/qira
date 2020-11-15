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

OBJS    = rtas.o of.o pci.o
OBJS2   = entry.o

all: 		oflib.o


oflib.o:	$(OBJS) $(OBJS2)
		$(LD) $(LDFLAGS) $^ -o oflib.o -r

clean:		
		$(RM) -f $(OBJS) $(OBJS2) oflib.o

include $(TOP)/make.depend


#mrproper : clean
#	rm -rf .depend 
#
#depend :
#	@rm -rf .depend ; touch .depend ; \
#	makedepend -v -f.depend -- $(CFLAGS) -- $(OBJS:.o=.c) 2> /dev/null ; \
#	$(CC) -M $(CFLAGS) $(OBJS2:.o=.S) >> .depend
