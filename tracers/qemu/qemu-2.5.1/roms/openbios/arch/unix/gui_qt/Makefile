#
# Makefile of QT user interface for OpenBIOS
# 
#  (C) 2004 Stefan Reinauer <stepan@openbios.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2
#   

include		../../../config/Makefile.top

XTARGETS                = qt

qt-OBJS                 = $(obj-y)
obj-y                   += gui_qt.o

QMAKE		= qmake
UIDIR	= $(shell pwd )
TOPDIR		= $(shell cd $(top_srcdir) ; pwd)
ABSOINC		= $(shell cd $(ARCHINCLUDES) 2> /dev/null ; pwd )

export UIDIR TOPDIR ABSOINC

$(ODIR)/makefile.qmake: gui-qt.pro Makefile
	@echo "ODIR: $(ODIR)"
	@test -d $(ODIR) || $(INSTALL) -d $(ODIR)
	@test -d $(ODIR)/qbuild || $(INSTALL) -d $(ODIR)/qbuild
	@install -m 644 gui-qt.pro $(ODIR)/
	cd $(ODIR) ; $(QMAKE) -o makefile.qmake

$(ODIR)/libgui_qt.a: $(ODIR)/makefile.qmake $(wildcard *.cpp)
	cd $(ODIR) ; $(MAKE) -f makefile.qmake
	@ln -f $(ODIR)/qbuild/libgui_qt.a $@

clean-local:
	@rm -f $(ODIR)/makefile.qmake
	@rm -rf $(QBUILDDIR)

INCLUDES	= -I$(top_srcdir)/include -DBOOTSTRAP

include		$(rules)/Rules.make
