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


STDIO_SRC_C = fscanf.c sprintf.c vfprintf.c vsnprintf.c vsprintf.c fprintf.c \
	      printf.c setvbuf.c putc.c puts.c putchar.c scanf.c stdchnls.c \
	      vfscanf.c vsscanf.c fileno.c

STDIO_SRC_ASM = 
STDIO_SRCS = $(STDIO_SRC_C:%=$(STDIOCMNDIR)/%) $(STDIO_SRC_ASM:%=$(STDIOCMNDIR)/%)
STDIO_OBJS = $(STDIO_SRC_C:%.c=%.o) $(STDIO_SRC_ASM:%.S=%.o)

%.o : $(STDIOCMNDIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
