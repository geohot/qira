# Invoke with PIN_ROOT=./pin-2.13-xxx TARGET=ia32 make
# Can also use intel64 for 64-bit.
ifndef PIN_ROOT
PIN_ROOT:=$(shell test -d pin-latest && echo pin-latest)
ifeq ($(PIN_ROOT),)
$(error Must define a PIN_ROOT or have a pin-latest)
endif
endif

CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

QIRAPINTOOL := $(OBJDIR)qirapin$(PINTOOL_SUFFIX)
TOOL_CXXFLAGS := $(TOOL_CXXFLAGS) -Wno-error

.PHONY: all runls
all: $(QIRAPINTOOL)

runls: all
	mkdir -p /tmp/qira_logs
	$(PIN_ROOT)/pin -t $(QIRAPINTOOL) -- ls -l

