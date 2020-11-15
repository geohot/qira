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

# FIXME review -I ...
# export NEW_BUILD=1

TOPCMNDIR	?= ../..
INCLCMNDIR	?= ../../include

include $(TOPCMNDIR)/make.rules


CPPFLAGS = -I$(INCLCMNDIR) -I$(INCLBRDDIR) -I.
CFLAGS += $(FLAG)

SRCS = build_ffs.c cfg_parse.c create_flash.c create_crc.c
OBJS = $(SRCS:%.c=%.o)

all: build_romfs

build_romfs: $(OBJS)
	$(HOSTCC) $(HOSTCFLAGS) $(FLAG) -o $@ $^

testing: build_romfs
	$(MAKE) -C test

%.o: %.c
	$(HOSTCC) $(CPPFLAGS) $(HOSTCFLAGS) $(FLAG) -c $< -o $@

clean:
	rm -f build_romfs *.o 

distclean: clean
	rm -f Makefile.dep


# Rules for creating the dependency file:
depend:
	rm -f Makefile.dep
	$(MAKE) Makefile.dep

Makefile.dep: Makefile
	$(HOSTCC) -MM $(CPPFLAGS) $(HOSTCFLAGS) $(SRCS) > Makefile.dep

# Include dependency file if available:
-include Makefile.dep
