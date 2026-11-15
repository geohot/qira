# Build libqira.so, the QIRA QEMU TCG plugin (Task 5).
#
# Needs glib-2.0 and the qemu-plugin.h of the QEMU it will run in. In the devenv
# shell both are provided and QEMU_PLUGIN_INCLUDE points at the header; otherwise
# pass QEMU_PLUGIN_INCLUDE=<qemu prefix>/include on the command line.

QEMU_PLUGIN_INCLUDE ?= /usr/include
CC      ?= cc
GLIB_CFLAGS := $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS   := $(shell pkg-config --libs glib-2.0)
CFLAGS  ?= -O2
override CFLAGS += -shared -fPIC -Wall -Wextra -I$(QEMU_PLUGIN_INCLUDE) $(GLIB_CFLAGS)

libqira.so: qira.c
	$(CC) $(CFLAGS) -o $@ $< $(GLIB_LIBS)

clean:
	rm -f libqira.so

.PHONY: clean
