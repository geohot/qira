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

include ../../make.rules

CFLAGS_COMLIB = -pedantic -std=gnu99 -O0
ASFLAGS_COMLIB =


COMLIBDIR 	= $(LLFWCMNDIR)/clib

COMLIB_SRC_ASM	=
COMLIB_SRC_C	= iolib.c

COMLIB_SRCS 	= $(COMLIB_SRC_ASM:%=$(COMLIBDIR)/%) \
		  $(COMLIB_SRC_C:%=$(COMLIBDIR)/%)
COMLIB_OBJ_ASM	= $(COMLIB_SRC_ASM:%.S=%.o)
COMLIB_OBJ_C	= $(COMLIB_SRC_C:%.c=%.o)


comlib.o:	$(COMLIB_OBJ_C) $(COMLIB_OBJ_ASM)
		$(LD) $(LDFLAGS) $^ -o $@ -r

%.o: $(LLFWCMNDIR)/clib/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_COMLIB) -c $< -o $@

%.o: $(LLFWCMNDIR)/clib/%.S
	$(CC) $(CPPFLAGS) $(ASFLAGS) $(ASFLAGS_COMLIB) -c $< -o $@

LLFW_CLEAN_TARGETS	+= clean_clib
.PHONY : clean_clib
clean_clib:
	rm -f $(COMLIB_OBJ_C) $(COMLIB_OBJ_ASM) comlib.o
