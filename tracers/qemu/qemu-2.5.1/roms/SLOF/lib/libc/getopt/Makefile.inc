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

GETOPT_SRC_C = getopt.c
GETOPT_OBJS = $(GETOPT_SRC_C:%.c=%.o)

%.o : $(GETOPTCMNDIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
