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

include clients.mk

all:
	for dir in $(CLIENTS); do \
		if [ -r $$dir/Makefile ]; then \
		$(MAKE) -C $$dir "FLAG=$(FLAG)" || exit 1; \
		cp $$dir/client $$dir.client; \
		fi; \
	done

clean distclean:
	@for dir in $(CLIENTS); do \
		if [ -r $$dir/Makefile ]; then \
		$(MAKE) -C $$dir $@ || exit 1; \
		rm -f $$dir.client; \
		fi; \
	done
