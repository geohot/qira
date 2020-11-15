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

OBJS =  init.o systemcall.o crt0.o timer.o
OBJS2 = entry.o

all: kernel.o 

kernel.o: $(OBJS) $(OBJS2)
		$(LD) $(LDFLAGS) $(OBJS) $(OBJS2) -o $@ -r

clean:		
		$(RM) -f *.o *.a *.i

include $(TOP)/make.depend
