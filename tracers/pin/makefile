##############################################################
#
#              THIS IS NOT A NORMAL MAKEFILE
#
##############################################################

# This integrates with Pin's makefile stuff.
# Invoke with `make TARGET=???`, where ??? is either ia32 or intel64
# If there isn't a pin-latest folder, PIN_ROOT must also be defined.

ifndef PIN_ROOT
PIN_ROOT:=$(shell test -d pin-latest && echo pin-latest)
ifeq ($(PIN_ROOT),)
$(error Must define a PIN_ROOT or have a pin-latest folder)
endif
endif

CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

QIRAPINTOOL := $(OBJDIR)qirapin$(PINTOOL_SUFFIX)
ifneq ($(TARGET_OS),windows)
TOOL_CXXFLAGS := $(TOOL_CXXFLAGS) -Wno-error
endif

$(shell mkdir -p '$(OBJDIR)')

.PHONY: all clean runls
all: $(QIRAPINTOOL)

clean:
	rm -Rf '$(OBJDIR)'

ifeq ($(TARGET_OS),mac)
runls: all
	cp -f /bin/ls /tmp/ls
	codesign -fs- /tmp/ls
	$(PIN_ROOT)/pin -t $(QIRAPINTOOL) -- /tmp/ls -l
else
ifeq ($(TARGET_OS),windows)
runls: all
	$(PIN_ROOT)/pin -t $(QIRAPINTOOL) -- "`cygpath -w /bin/ls`" -l
else
runls: all
	$(PIN_ROOT)/pin -t $(QIRAPINTOOL) -- /bin/ls -l
endif
endif
