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

include ../make.rules

all: gen_reloc_table

%.o: %.c
		$(HOSTCC) -W $(HOSTCFLAGS) -c $^

elf2tst:	elf2tst.o
		$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

gen_reloc_table: gen_reloc_table.o
		$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

clean_here:
	rm -f elf2tst *.o gen_reloc_table

clean:	clean_here


distclean:	clean_here

