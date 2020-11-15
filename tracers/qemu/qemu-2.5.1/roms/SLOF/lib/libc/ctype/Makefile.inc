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


CTYPE_SRC_C = isdigit.c isprint.c isspace.c isxdigit.c tolower.c toupper.c
CTYPE_SRC_ASM = 
CTYPE_SRCS = $(CTYPE_SRC_C:%=$(CTYPECMNDIR)/%) $(CTYPE_SRC_ASM:%=$(CTYPECMNDIR)/%)
CTYPE_OBJS = $(CTYPE_SRC_C:%.c=%.o) $(CTYPE_SRC_ASM:%.S=%.o)

%.o : $(CTYPECMNDIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
