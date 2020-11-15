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

SRCS = nvram.c envvar.c

TOPCMNDIR ?= ../..

include $(TOPCMNDIR)/make.rules

ASFLAGS = $(FLAG) $(RELEASE) $(CPUARCHDEF) -Wa,-mregnames
CPPFLAGS = -I../libc/include $(CPUARCHDEF) $(FLAG) \
	   -I$(INCLBRDDIR) -I$(INCLCMNDIR)/$(CPUARCH) -I. -I../../include
LDFLAGS = -nostdlib

TARGET = ../libnvram.a

all: $(TARGET)

OBJS = $(SRCS:%.c=%.o)

$(TARGET): $(OBJS)
	$(AR) -rc $@ $(OBJS)
	$(RANLIB) $@


clean:
	$(RM) $(TARGET) $(OBJS)

distclean: clean
	$(RM) Makefile.dep


# Rules for creating the dependency file:
depend:
	$(RM) Makefile.dep
	$(MAKE) Makefile.dep

Makefile.dep: Makefile
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $(SRCS) > Makefile.dep


# Include dependency file if available:
-include Makefile.dep

