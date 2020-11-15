# tag: qmake project file for OpenBIOS QT user interface
#
# Copyright (C) 2003-2004 Stefan Reinauer <stepan@openbios.org>
#
# See the file "COPYING" for further information about
# the copyright and warranty status of this work.
#

TEMPLATE    = lib
CONFIG     += qt thread warn_on release staticlib
LIBS	    = 
INCLUDEPATH = qbuild $(ABSOINC) $(TOPDIR)/include
DESTDIR     = qbuild
OBJECTS_DIR = qbuild
MOC_DIR     = qbuild
TARGET      = gui_qt
HEADERS	    = $(UIDIR)/gui-qt.h
SOURCES	    = $(UIDIR)/gui-qt.cpp $(UIDIR)/qt-main.cpp
