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
CPPFLAGS = -I../libc/include $(CPUARCHDEF) -I$(INCLBRDDIR) \
	   -I$(INCLCMNDIR) -I$(INCLCMNDIR)/$(CPUARCH) -I$(SLOFCMNDIR)
LDFLAGS = -nostdlib

TARGET = ../libusb.a


all: $(TARGET)

SRCS =  usb-core.c usb-ohci.c usb-ehci.c usb-slof.c usb-key.c usb-hid.c \
	usb-hub.c usb-xhci.c

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
	$(CC) -M $(CPPFLAGS) $(CFLAGS) $(SRCS) $(SRCSS) > Makefile.dep

# Include dependency file if available:
-include Makefile.dep
