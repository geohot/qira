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

# Before including this Makefile, you should specify the following variables
# in your Makefile:
# - RTASCMNDIR : Points to the common RTAS directory
# - RTASBRDDIR : Points to the board specific RTAS directory
# - TOOLSDIR : Points to the common tools directory
# - OBJS : A list with all object files that should be linked into rtas.bin
# - BOARD_SRCS : A list with all board specific source code files
#                (needed for "make depend")


LDFLAGS		= -nostdlib
CPPFLAGS	+= -I$(RTASBRDDIR) -I$(RTASCMNDIR) \
		  -I$(INCLCMNDIR) -I$(INCLBRDDIR) \
		  -I$(LIBCMNDIR)/libc/include \
		  -I$(INCLCMNDIR)/$(CPUARCH)
ASFLAGS		= -Wa,-mregnames $(FLAG)
CFLAGS		+= -g -nostdinc -ffreestanding -Wall -Wextra -O2 -msoft-float \
		  -mno-altivec -mabi=no-altivec $(FLAG)

# Common RTAS files:
RTAS_SRC_ASM	= reloc.S rtas_common.S rtas_entry.S rtas_term.S \
		  rtas_cpu.S rtas_flash_asm.S rtas_mem.S rtas_ras.S
RTAS_SRC_C	= rtas_call.c rtas_flash_c.c rtas_h8.c \
		  rtas_nvramlog.c rtas_sensor.c rtas_init.c \
		  rtas_flash_cfi.c
RTAS_SRCS	= $(RTAS_SRC_ASM) $(RTAS_SRC_C)
RTAS_OBJ_ASM	= $(RTAS_SRC_ASM:%.S=%.o)
RTAS_OBJ_C	= $(RTAS_SRC_C:%.c=%.o)

# Common build rules:
$(RTAS_OBJ_C):
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(@:%.o=$(RTASCMNDIR)/%.c) -o $@

$(RTAS_OBJ_ASM):
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c $(@:%.o=$(RTASCMNDIR)/%.S) -o $@

$(TOOLSDIR)/gen_reloc_table: $(TOOLSDIR)/gen_reloc_table.c
	$(MAKE) -C $(TOOLSDIR) gen_reloc_table


# Rules for building rtas.bin:
rtas.bin: rtas
	$(OBJCOPY) -O binary $< $@

rtas: $(RTASCMNDIR)/rtas.lds $(OBJS) reloc_table.o $(LIBCMNDIR)/libc.a
	$(LD) $(LDFLAGS) -o $@ -T $(RTASCMNDIR)/rtas.lds $(OBJS) \
	    reloc_table.o $(LIBCMNDIR)/libc.a

reloc_table.o: $(TOOLSDIR)/gen_reloc_table $(OBJS) $(LIBCMNDIR)/libc.a
	$(TOOLSDIR)/create_reloc_table.sh --ld "$(ONLY_LD)" --ldflags "$(LDFLAGS)" \
	  --lds "$(RTASCMNDIR)/rtas.lds" --objcopy "$(OBJCOPY)" $(OBJS)  $(LIBCMNDIR)/libc.a


$(LIBCMNDIR)/libc.a:
	$(MAKE) -C $(LIBCMNDIR) libc


# Rules for cleaning up:
clean_rtas:
	rm -f $(OBJS) reloc_table.o rtas rtas.bin
	rm -f $(RTASCMNDIR)/*~ $(RTASCMNDIR)/*.o

distclean_rtas: clean_rtas
	rm -f Makefile.dep


# Rules for creating the dependency file:
depend:
	rm -f Makefile.dep
	$(MAKE) Makefile.dep

Makefile.dep: Makefile $(RTASCMNDIR)/Makefile.inc
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $(RTAS_SRCS:%=$(RTASCMNDIR)/%) > Makefile.dep
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $(BOARD_SRCS) >> Makefile.dep

# Include dependency file if available:
-include Makefile.dep
