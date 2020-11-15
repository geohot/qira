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

IOGENERICDIR 	= $(LLFWCMNDIR)/io_generic

IO_GENERIC_SRC_ASM	= io_generic.S
IO_GENERIC_SRC_C	= 

IO_GENERIC_SRCS 	= $(IO_GENERIC_SRC_ASM:%=$(IOGENERICDIR)/%) \
			  $(IO_GENERIC_SRC_C:%=$(IOGENERICDIR)/%)
IO_GENERIC_OBJ_ASM	= $(IO_GENERIC_SRC_ASM:%.S=%.o)
IO_GENERIC_OBJ_C	= $(IO_GENERIC_SRC_C:%.c=%.o)


io_generic_lib.o:	$(IO_GENERIC_OBJ_ASM) $(IO_GENERIC_OBJ_C)
	$(LD) $(LDFLAGS) $^ -o $@ -r


%.o: $(IOGENERICDIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

%.o: $(IOGENERICDIR)/%.S
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c $< -o $@


LLFW_CLEAN_TARGETS	+= clean_io_generic
.PHONY : clean_io_generic
clean_io_generic:
	rm -f $(IO_GENERIC_OBJ_C) $(IO_GENERIC_OBJ_ASM) io_generic_lib.o
