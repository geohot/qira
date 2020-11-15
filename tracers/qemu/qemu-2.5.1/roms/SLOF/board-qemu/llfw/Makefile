# *****************************************************************************
# * Copyright (c) 2004, 2011 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/

include ../../make.rules

CPPFLAGS	= -I$(INCLBRDDIR) -I$(INCLCMNDIR) -I$(INCLCMNDIR)/$(CPUARCH) \
		  -I$(LIBCMNDIR)/libc/include
CFLAGS		+= -fno-builtin $(FLAG) $(CPPFLAGS) -O2  -msoft-float $(MAMBO)
CFLAGS		+= $(BOOT) $(IOCONF) -Wa,-mregnames $(RELEASE) $(CPUARCHDEF) -Wall
ASFLAGS         = $(BOOT) $(IOCONF) $(RELEASE)$(CPUARCHDEF)  -Wa,-mregnames
LDFLAGS1	= -nostdlib -e__start -Tstage2.lds -N -Ttext=0x100


STG1OBJ		 = startup.o version.o boot_abort.o romfs.o io_generic.o board_io.o 
STG1OBJ		 += stage2_head.o stage2.o comlib.o romfs_wrap.o nvramlog.o

.PHONY: version.S

all: stage1.bin Cboot.o

stage1.bin:	$(STG1OBJ) $(LIBCMNDIR)/libelf.a $(LIBCMNDIR)/libc.a \
		$(LIBCMNDIR)/libhvcall.a
		$(LD) $(LDFLAGS1) -o stage1.elf $^
		$(OBJCOPY) -O binary stage1.elf $@

romfs.o:	../../llfw/romfs.S
		$(CC) $(CFLAGS) -c ../../llfw/romfs.S

boot_abort.o:	../../llfw/boot_abort.S
		$(CC) $(CFLAGS) -c ../../llfw/boot_abort.S

nvramlog.o:	../../llfw/nvramlog.S
		$(CC) $(CFLAGS) -c ../../llfw/nvramlog.S

include $(LLFWCMNDIR)/clib/Makefile.inc

include $(LLFWCMNDIR)/io_generic/Makefile.inc

romfs_wrap.o:	../../llfw/romfs_wrap.c
		$(CC) $(CFLAGS) -c ../../llfw/romfs_wrap.c

Cboot.o: Cboot.S
		$(CC) $(CFLAGS) -c $^
		$(OBJCOPY) -O binary Cboot.o Cboot.bin

%.o: %.S
		$(CC) $(CFLAGS) -c $^

clean:
		rm -f *.o *.bin *.elf
