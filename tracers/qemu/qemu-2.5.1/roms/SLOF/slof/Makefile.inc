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
# - INCLCMNDIR : Points to the common include directory
# - INCLCMNDIR : Points to the board specific include directory
# - SLOFCMNDIR : Points to the common SLOF directory
# - SLOFBRDDIR : Points to the board specific SLOF directory
# - LLFWCMNDIR : Points to the common LLFW directory
# - LLFWBRDDIR : Points to the board specific LLFW directory

# Set LLFW directories (should normally be set from parent Makefile):
TOPBRDDIR ?= $(shell cd .. && pwd)
LLFWBRDDIR ?= $(TOPBRDDIR)/llfw
LLFWCMNDIR ?= $(SLOFCMNDIR:%/slof=%/llfw)
INCLBRDDIR ?= $(TOPBRDDIR)/include


CPPFLAGS += -I. -I$(INCLCMNDIR) -I$(INCLBRDDIR) -I$(INCLCMNDIR)/$(CPUARCH)
CFLAGS  = -DTARG=$(TARG) -static -Wall -W -std=gnu99 \
	  -O2 -fomit-frame-pointer -msoft-float $(FLAG) $(CPUARCHDEF) \
	  -fno-stack-protector -fno-strict-aliasing 
ASFLAGS = -Wa,-mpower4 -Wa,-mregnames $(FLAG) $(CPUARCHDEF)

LDFLAGS += -static -nostdlib -Wl,-q,-n

ifneq ($(TARG),unix)
CFLAGS	+= -nostdinc -fno-builtin
CPPFLAGS += -I$(LIBCMNDIR)/libc/include
SLOF_LIBS += $(LIBCMNDIR)/libc.a
endif

DICT = $(SLOFCMNDIR)/prim.in $(SLOFCMNDIR)/engine.in \
	$(BOARD_SLOF_IN) $(SLOFCMNDIR)/$(TARG).in

# Source code files with automatic dependencies:
SLOF_BUILD_SRCS = paflof.c helpers.c allocator.c

# Flags for pre-processing Forth code with CPP:
FPPFLAGS = -nostdinc -traditional-cpp -undef -P -C $(FLAG)
FPPINCLUDES ?= -I$(SLOFBRDDIR) -I$(SLOFCMNDIR)/fs

# Rules for pre-processing Forth code:
# - Use CPP for pre-processing #include directives
# - Use sed to strip all white spaces at the beginning of a line
# - Use sed to remove all lines that only contain a comment
# - Use sed to remove all empty lines from the file
%.fsi: %.fs
ifeq ($(V),1)
	printf "\t[FPP]\t%s\n" `basename "$@"`
endif
	rm -f $@
	cpp $(FPPFLAGS) $(FPPINCLUDES) $< > $@.tmp
	sed -e 's/^[	 ]*//' < $@.tmp \
	  | sed -e '/^\\[	 ]/d' \
	  | sed -e '/^([	 ][^)]*[	 ])[	 ]*$$/d' \
	  | sed -e '/^$$/d' > $@
	rm -f $@.tmp


OF.o:	OF.fsi
	$(LD) -o $@ -r -bbinary $<


dict.xt: $(DICT) $(SLOFCMNDIR)/ref.pl 
	cat $(DICT) | perl $(SLOFCMNDIR)/ref.pl -s $(CELLSIZE) > dict.xt

ifdef BOARD_SLOF_CODE
board.code: $(BOARD_SLOF_CODE)
	cat $(BOARD_SLOF_CODE) > $@
else
board.code:
	echo > $@
endif

paflof: $(SLOFCMNDIR)/OF.lds $(SLOFCMNDIR)/ofw.o paflof.o $(SLOFCMNDIR)/entry.o \
	helpers.o allocator.o romfs.o version.o OF.o nvramlog.o $(LLFWBRDDIR)/board_io.o \
	$(LLFWBRDDIR)/io_generic_lib.o $(SLOF_LIBS)
	$(CC) -T$(SLOFCMNDIR)/OF.lds $(SLOFCMNDIR)/ofw.o version.o paflof.o helpers.o allocator.o \
	$(SLOFCMNDIR)/entry.o romfs.o OF.o nvramlog.o $(LLFWBRDDIR)/board_io.o \
	$(LLFWBRDDIR)/io_generic_lib.o $(LDFLAGS) $(SLOF_LIBS) -o $@
	#save a copy of paflof before stripping
	@cp $@ $@.unstripped
	$(STRIP) --strip-unneeded $@

paflof.o: board.code dict.xt
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(SLOFCMNDIR)/paflof.c

helpers.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(SLOFCMNDIR)/helpers.c

allocator.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(SLOFCMNDIR)/allocator.c

$(SLOFCMNDIR)/xvect.bin: $(SLOFCMNDIR)/lowmem.o
	$(CC) $(LDFLAGS) -Wl,--oformat,binary -Ttext=0x100 -o xvect.bin.tmp $<
	dd if=xvect.bin.tmp of=$(SLOFCMNDIR)/xvect.bin bs=256 skip=1 2>/dev/null
	rm -f xvect.bin.tmp

romfs.o:
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c -o $@ $(LLFWCMNDIR)/romfs.S

nvramlog.o:
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c -o $@ $(LLFWCMNDIR)/nvramlog.S

checkpoint.o:
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c -o $@ $(LLFWCMNDIR)/checkpoint.S

$(LLFWBRDDIR)/board_io.o:
	$(MAKE) -C $(LLFWBRDDIR) board_io.o

$(LLFWBRDDIR)/io_generic_lib.o:
	$(MAKE) -C $(LLFWBRDDIR) io_generic_lib.o

default-font.o: $(SLOFCMNDIR)/default-font.c
	$(CC) $(CPPFLAGS) $< -c -o default-font.o

$(SLOFBRDDIR)/default-font.bin: default-font.o
	$(OBJCOPY) -Obinary default-font.o $@ 

.PHONY : create_OF.ffs clean_slof distclean_slof depend


# Create OF.ffs automatically from file list in OF_FFS_FILES variable.
# We have to use absolute path names there, so we have to use `pwd` to
# find them out:
create_OF_ffs:
	rm -f OF.ffs
	@for i in $(OF_FFS_FILES) ; do \
		CURRENTDIR=`pwd` ; cd `dirname $$i` ; \
		DIRNAME=`pwd` ; cd $$CURRENTDIR ; \
		echo `basename $$i | sed  -e s/\.fsi/\.fs/` \
		     $$DIRNAME/`basename $$i` 0 0 >> OF.ffs ; \
	 done


# Targets for cleaning up:
clean_slof:
	rm -f $(SLOFCMNDIR)/*.o $(SLOFCMNDIR)/*.bin $(SLOFCMNDIR)/*.elf
	rm -f dict.xt board.code paflof paflof.unstripped default-font.bin
	rm -f $(filter %.fsi,$(OF_FFS_FILES))

distclean_slof:	clean_slof
	rm -f Makefile.dep


# Rules for creating the dependency file:
depend:
	rm -f Makefile.dep
	$(MAKE) Makefile.dep

Makefile.dep: Makefile $(SLOFCMNDIR)/Makefile.inc OF.fs
	$(CC) -M -MG $(CPPFLAGS) $(CFLAGS) $(SLOF_BUILD_SRCS:%=$(SLOFCMNDIR)/%) > Makefile.dep
	cpp -M -MG $(FPPFLAGS) $(FPPINCLUDES) -MT OF.fsi OF.fs >> Makefile.dep
	for i in $(filter %.fsi,$(OF_FFS_FILES)) ; do \
		cpp -M -MG $(FPPFLAGS) $(FPPINCLUDES) -MT $$i \
			`echo $$i | sed  -e 's/\.fsi/\.fs/'` >> Makefile.dep ; \
	done

# Include dependency file if available:
-include Makefile.dep
