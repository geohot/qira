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


STRING_SRC_C = strcat.c strchr.c strcmp.c strcpy.c strlen.c strncmp.c \
		strncpy.c strstr.c memset.c memcpy.c memmove.c memchr.c \
		memcmp.c strcasecmp.c strncasecmp.c strtok.c
STRING_SRC_ASM = 
STRING_SRCS = $(STRING_SRC_C:%=$(STRINGCMNDIR)/%) $(STRING_SRC_ASM:%=$(STRINGCMNDIR)/%)
STRING_OBJS = $(STRING_SRC_C:%.c=%.o) $(STRING_SRC_ASM:%.S=%.o)

%.o : $(STRINGCMNDIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
