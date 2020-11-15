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

ROOTDIR ?= ../..

LDFLAGS		=
ASFLAGS		= -I./include -Wa,-mregnames

#NOTE: -DDEBUG only needed for debugging/tracing...
CFLAGS		= -UDEBUG -m64 -I. -I./include -I./include/x86emu \
		  -I$(TOP)/clients/net-snk/include -I$(ROOTDIR)/include \
		  -I$(ROOTDIR)/lib/libc/include -O3 -nostdinc -fno-builtin \
		  -ffreestanding -Wall -Wno-unused

X86EMU_OBJS	= debug.o decode.o fpu.o ops2.o ops.o prim_ops.o sys.o

%.o: %.S
		$(CC) $(ASFLAGS) -c -o $@  $^

%.o: %.c
		$(CC) $(CFLAGS) -c -o $@ $^

all: libx86emu.a

libx86emu.a: $(X86EMU_OBJS)
	$(AR) -rc $@ $^
	$(RANLIB) $@

clean:
	$(RM) *.o *.i *.s libx86emu.a 

distclean: clean

