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


STDLIB_SRC_C =  error.c atoi.c atol.c strtoul.c strtol.c rand.c \
		 malloc.c memalign.c realloc.c free.c
		
STDLIB_SRC_ASM = 
STDLIB_SRCS = $(STDLIB_SRC_C:%=$(STDLIBCMNDIR)/%) $(STDLIB_SRC_ASM:%=$(STDLIBCMNDIR)/%)
STDLIB_OBJS = $(STDLIB_SRC_C:%.c=%.o) $(STDLIB_SRC_ASM:%.S=%.o)

%.o : $(STDLIBCMNDIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
