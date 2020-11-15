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

TOPCMNDIR ?= ../..

include $(TOPCMNDIR)/make.rules

ASFLAGS = $(FLAG) $(RELEASE) $(CPUARCHDEF) -Wa,-mregnames
CPPFLAGS = -I../libc/include $(CPUARCHDEF) -I$(INCLBRDDIR) -I. -I../../include
LDFLAGS = -nostdlib

TARGET = ../libbootmsg.a


all: $(TARGET)

ifeq ($(CPUARCH),cbea)
SRCS =
SRCSS = bootmsg_lvl.S
else 
ifeq ($(CPUARCH),ppc970)
SRCS =
SRCSS = bootmsg_lvl.S
else 
ifeq ($(CPUARCH),p5)
SRCS =
SRCSS = bootmsg_lvl.S
else
ifeq ($(CPUARCH),ppcp7)
SRCS =
SRCSS = bootmsg_lvl.S
else
SRCS = bootmsg.c
SRCSS = 
endif
endif
endif
endif

OBJS = $(SRCS:%.c=%.o) $(SRCSS:%.S=%.o)

$(TARGET): $(OBJS)
	$(AR) -rc $@ $(OBJS)
	$(RANLIB) $@

%.o: %.S
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c $< -o $@

clean:
	$(RM) $(TARGET) $(OBJS)

distclean: clean
	$(RM) Makefile.dep


# Rules for creating the dependency file:
depend:
	$(RM) Makefile.dep
	$(MAKE) Makefile.dep

Makefile.dep: Makefile
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $(SRCS) $(SRCSS) > Makefile.dep

# Include dependency file if available:
-include Makefile.dep

