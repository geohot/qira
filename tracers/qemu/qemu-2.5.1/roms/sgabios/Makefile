# Copyright 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Id$

BUILD_DATE = \"$(shell date -u)\"
BUILD_SHORT_DATE = \"$(shell date -u +%D)\"
BUILD_HOST = \"$(shell hostname)\"
BUILD_USER = \"$(shell whoami)\"

CFLAGS := -Wall -Os -m32 -nostdlib

ASFLAGS := $(CFLAGS)
ASFLAGS += -DBUILD_DATE="$(BUILD_DATE)"
ASFLAGS += -DBUILD_SHORT_DATE="$(BUILD_SHORT_DATE)"
ASFLAGS += -DBUILD_HOST="$(BUILD_HOST)"
ASFLAGS += -DBUILD_USER="$(BUILD_USER)"

LDSCRIPT := rom16.ld
LDFLAGS := -T $(LDSCRIPT) -nostdlib
OBJCOPY := objcopy

ASRCS = sgabios.S

CSRCS =

SRCS = $(CSRCS) $(ASRCS)

OBJS = ${CSRCS:.c=.o} ${ASRCS:.S=.o}
INCS = ${CSRCS:.c=.h} ${ASRCS:.S=.h}

PROGS = sgabios.bin csum8

.SUFFIXES: .bin .elf
.PHONY: buildinfo

all: $(PROGS)

sgabios.bin: sgabios.elf
	$(OBJCOPY) -O binary $< $@
	./csum8 $@

sgabios.elf: .depend $(OBJS) $(LDSCRIPT) csum8
	$(LD) $(LDFLAGS) $(OBJS) -o $@

csum8: csum8.c
	$(CC) -Wall -O2 -o $@ $<

sgabios.o: buildinfo


buildinfo:
	touch sgabios.S
clean:
	$(RM) $(PROGS) $(OBJS) *.elf *.srec *.com version.h

.depend:: $(INCS) $(SRCS) Makefile
	$(RM) .depend
	$(CPP) -M $(CFLAGS) $(SRCS) >.tmpdepend && mv .tmpdepend .depend

ifeq (.depend, $(wildcard .depend))
include .depend
else
# if no .depend file existed, add a make clean to the end of building .depend
.depend::
	$(MAKE) clean
endif
