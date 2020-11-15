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

include ../Makefile.dirs

include $(TOPBRDDIR)/config
include $(TOPCMNDIR)/make.rules


LDFLAGS		= -nostdlib
CPPFLAGS	= -I. -I$(LIBCMNDIR)/libc/include -I$(LIBCMNDIR)/libipmi -I$(INCLBRDDIR) \
		  -I$(INCLCMNDIR) -I$(RTASCMNDIR) -I$(INCLCMNDIR)/$(CPUARCH)
ASFLAGS		= -Wa,-mregnames $(FLAG)
CFLAGS		+= -Wall -Wextra -O2 -msoft-float -ffreestanding $(FLAG)

# Board specific RTAS files:
BOARD_SRC_ASM	=
BOARD_SRC_C	= rtas_flash.c rtas_board.c rtas_pci.c  \
		  rtas_out.c rtas_table.c 
BOARD_SRCS	= $(BOARD_SRC_ASM) $(BOARD_SRC_C)
BOARD_OBJ	= $(BOARD_SRC_ASM:%.S=%.o) $(BOARD_SRC_C:%.c=%.o) $(BOARD_OCO:%.oco=%.o)
BOARD_OCO	= i2c_bmc.oco ipmi_oem.oco


# Common RTAS files (from $(RTASCMNDIR) directory):
RTAS_SRC_ASM	= rtas_entry.S rtas_common.S reloc.S
RTAS_SRC_C	= rtas_call.c
RTAS_SRCS	= $(RTAS_SRC_ASM) $(RTAS_SRC_C)
RTAS_OBJ	= $(RTAS_SRC_ASM:%.S=%.o) $(RTAS_SRC_C:%.c=%.o)

RTAS_FLASH_SRC  = block_lists.c
RTAS_FLASH_OBJ  = $(RTAS_FLASH_SRC:%.c=$(RTASCMNDIR)/flash/%.o)

# Additional object files:
EXTRA_OBJ	= ../llfw/hw.o ../../lib/libc.a ../../lib/libipmi.a

OBJS 		= $(RTAS_OBJ:%=$(RTASCMNDIR)/%) $(BOARD_OBJ) $(EXTRA_OBJ) \
		  $(RTAS_FLASH_OBJ)


all:	Makefile.dep rtas.bin

rtas.bin: rtas 
	$(OBJCOPY) -O binary $< $@

rtas: $(RTASCMNDIR)/rtas.lds $(OBJS) reloc_table.o 
	$(LD) $(LDFLAGS) -o $@ -T $(RTASCMNDIR)/rtas.lds $(OBJS) reloc_table.o

reloc_table.o: $(TOOLSDIR)/gen_reloc_table $(OBJS)
	$(TOOLSDIR)/create_reloc_table.sh --ld "$(ONLY_LD)" --ldflags "$(LDFLAGS)" \
	  --lds "$(RTASCMNDIR)/rtas.lds" --objcopy "$(OBJCOPY)" $(OBJS)

$(TOOLSDIR)/gen_reloc_table: $(TOOLSDIR)/gen_reloc_table.c
	$(MAKE) -C $(TOOLSDIR) gen_reloc_table

../../lib/libc.a:
	$(MAKE) -C ../../lib

clean:
	$(MAKE) -C ../../lib clean
	rm -f $(OBJS) reloc_table.o rtas rtas.bin

distclean : clean
	rm -f Makefile.dep


# Rules for creating the dependency file:
depend:
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $(BOARD_SRCS) > Makefile.dep
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $(RTAS_SRCS:%=$(RTASCMNDIR)/%) \
	  | sed -e '/:/s,^,$(RTASCMNDIR)/,' >> Makefile.dep
Makefile.dep:
	$(MAKE) depend

# Include dependency file if available:
ifneq (,$(wildcard Makefile.dep))
include Makefile.dep
endif
%.o: %.oco
	cp -f $< $@
