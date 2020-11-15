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

CFLAGS += -I../

ifeq ($(SNK_USE_MTFTP), 1)
CFLAGS += -DUSE_MTFTP
endif

OBJS    = ethernet.o ipv4.o udp.o tcp.o  dns.o bootp.o \
	  dhcp.o ipv6.o dhcpv6.o icmpv6.o ndp.o

ifeq ($(SNK_USE_MTFTP), 1)
OBJS += mtftp.o
else
OBJS += tftp.o
endif

all: netlib.o

netlib.o: $(OBJS) 
		$(LD) $(LDFLAGS) $^ -o $@ -r

clean:	
		$(RM) -f *.o *.a *.i

include $(TOP)/make.depend
