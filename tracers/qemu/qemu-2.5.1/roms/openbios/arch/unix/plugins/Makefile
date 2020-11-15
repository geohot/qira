
include				../../../config/Makefile.top

SUBDIRS-$(CONFIG_PLUGIN_PCI)	+= plugin_pci
SUBDIRS-$(CONFIG_PLUGIN_QT)	+= plugin_qt

PROGRAMS			= # loader
loader-OBJS			= loader.o
loader-LDFLAGS			= -dynamic $(LIBDL_LDFLAGS)

INCLUDES			= -DBOOTSTRAP

include				$(rules)/Rules.make
