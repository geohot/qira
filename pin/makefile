# Invoke with PIN_ROOT=./pin-2.13-xxx TARGET=ia32 make
# Can also use intel64 for 64-bit.
ifndef PIN_ROOT
$(error Must define a PIN_ROOT)
endif

CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

all: $(OBJDIR)qirapin$(PINTOOL_SUFFIX)
