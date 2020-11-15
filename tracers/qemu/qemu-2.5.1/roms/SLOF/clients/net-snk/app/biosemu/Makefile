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

CFLAGS += -I$(ROOTDIR)/other-licence/x86emu -I$(ROOTDIR)/other-licence/x86emu/include

OBJS    = biosemu.o debug.o device.o mem.o io.o interrupt.o vbe.o
LIBX86EMU = $(ROOTDIR)/other-licence/x86emu/libx86emu.a 

.PHONY: $(LIBX86EMU)

all: biosemu_app.o

# special rule for libx86emu.a
$(LIBX86EMU):
	$(MAKE) -C $(dir $@)

biosemu_app.o: $(OBJS) $(LIBX86EMU)
	$(LD) $(LDFLAGS) $^ -o $@ -r
	
clean:	
		$(RM) -f *.o *.a *.i *.s

include $(TOP)/make.depend
