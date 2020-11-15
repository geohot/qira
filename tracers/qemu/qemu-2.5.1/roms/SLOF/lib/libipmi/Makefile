# *****************************************************************************
# * Copyright (c) 2004, 2007 IBM Corporation
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

LIBIPMICMNDIR = $(shell pwd)

include $(TOPCMNDIR)/make.rules

TARGET = ../libipmi.a

all: $(TARGET)

$(TARGET):
	cp libipmi.oco $@

clean:

distclean:
