# tag: qmake project file for OpenBIOS QT plugin
#
# Copyright (C) 2003 Stefan Reinauer
#
# See the file "COPYING" for further information about
# the copyright and warranty status of this work.
#

TEMPLATE    = app
CONFIG     += qt thread warn_on release
LIBS	    = -shared
INCLUDEPATH = qbuild $(ABSOINC) $(TOPDIR)/include $(PLUGINDIR)/plugin_pci
DESTDIR     = qbuild
OBJECTS_DIR = qbuild
MOC_DIR     = qbuild
TARGET      = plugin_qt.so
HEADERS	    = $(PLUGINDIR)/plugin_qt/plugin_qt.h
SOURCES	    = $(PLUGINDIR)/plugin_qt/plugin_qt.cpp $(PLUGINDIR)/plugin_qt/qt_main.cpp
