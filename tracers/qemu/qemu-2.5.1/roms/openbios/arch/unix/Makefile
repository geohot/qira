# 

include			../../config/Makefile.top

SUBDIRS-$(CONFIG_PLUGINS)	= plugins
SUBDIRS-$(CONFIG_UNIX_QT)	= gui_qt

DICTIONARIES		= unix
unix-SRC		= tree.fs $(ARCHDICT_SRC)

PROGRAMS		= unix

unix-OBJS               = $(unix-y)
unix-y			+= blk.o 
unix-y			+= boot.o 
unix-y			+= unix.o 
unix-y			+= $(KOBJS) 
unix-y			+= $(MODULE_LIBS) $(FS_LIBS) $(DRIVER_LIBS) $(LIBC_LIBS)
unix-$(CONFIG_PLUGINS)  += plugins.o 

unix-LDFLAGS		= $(unix-LDFLAGS-$(CONFIG_PLUGINS))
unix-LDFLAGS-y		= -rdynamic $(LIBDL_LDFLAGS)
unix-LDFLAGS-n		= 
unix-LDADD		= 

INCLUDES		= -I../../kernel -I../../kernel/include -DBOOTSTRAP

include			$(rules)/Rules.forth
include			$(rules)/Rules.make
