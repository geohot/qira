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

LIBCCMNDIR = $(shell pwd)
STRINGCMNDIR = $(LIBCCMNDIR)/string
CTYPECMNDIR = $(LIBCCMNDIR)/ctype
STDLIBCMNDIR = $(LIBCCMNDIR)/stdlib
STDIOCMNDIR = $(LIBCCMNDIR)/stdio
GETOPTCMNDIR = $(LIBCCMNDIR)/getopt

include $(TOPCMNDIR)/make.rules


CPPFLAGS = -I$(LIBCCMNDIR)/include
LDFLAGS= -nostdlib

TARGET = ../libc.a


all: $(TARGET)

# Use the following target to build a native version of the lib
# (for example for debugging purposes):
native:
	$(MAKE) CROSS="" CC=$(HOSTCC) NATIVEBUILD=1


include $(STRINGCMNDIR)/Makefile.inc
include $(CTYPECMNDIR)/Makefile.inc
include $(STDLIBCMNDIR)/Makefile.inc
include $(STDIOCMNDIR)/Makefile.inc
include $(GETOPTCMNDIR)/Makefile.inc

OBJS = $(STRING_OBJS) $(CTYPE_OBJS) $(STDLIB_OBJS) $(STDIO_OBJS) $(GETOPT_OBJS)

ifneq ($(NATIVEBUILD),1)
# These parts of the libc use assembler, so they can only be compiled when
# we are _not_ building a native version.
endif


$(TARGET): $(OBJS)
	$(AR) -rc $@ $(OBJS)
	$(RANLIB) $@


clean:
	$(RM) $(TARGET) $(OBJS)

distclean: clean
