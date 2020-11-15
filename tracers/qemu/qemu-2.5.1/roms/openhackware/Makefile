#
#  <Makefile>
#     
#  Makefile for Open Hack'Ware.
#  
#  Copyright (C) 2004-2005 Jocelyn Mayer (l_indien@magic.fr)
#  
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License V2
#   as published by the Free Software Foundation
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

#DEBUG=1

CROSS_COMPILE?=powerpc-linux-
CC:= $(CROSS_COMPILE)gcc -m32
LD:= $(CROSS_COMPILE)ld -m elf32ppc
OBJCOPY:= $(CROSS_COMPILE)objcopy
MKDIR:= mkdir
CAT:= cat
TAR:= tar
RM:= rm -rf --
ECHO:= echo
ifeq ("$(DEBUG)", "1")
DEBUG:= $(ECHO)
else
DEBUG:= \#
endif

BUILD_DATE:= $(shell date -u +%F)
BUILD_TIME:= $(shell date -u +%T)

OBJDIR:= .objs
DISTDIR:= .
SRCDIR:= src

CC_BASE:= $(shell $(CC) -print-search-dirs | grep install | sed -e 's/.*\ //')
CFLAGS= -Wall -W -Werror -O2 -g -fno-builtin -fno-common -nostdinc -mregnames
# Disable a few warnings that would just create needless code churn
CFLAGS+= -Wno-pointer-sign -Wno-unused-but-set-variable
CFLAGS+= -DBUILD_DATE=$(BUILD_DATE) -DBUILD_TIME=$(BUILD_TIME)
CFLAGS+= -I$(SRCDIR)/ -I$(SRCDIR)/libc/include -I$(CC_BASE)/include
CFLAGS+= -I$(SRCDIR)/dev -I$(SRCDIR)/dev/block -I$(SRCDIR)/dev/char
CFLAGS+= -I$(SRCDIR)/dev/bus
LDFLAGS= -O2 -g -nostdlib

BIOS_IMAGE_BITS:= 20
BIOS_IMAGE_SIZE:= $(shell echo $$(( 1 << $(BIOS_IMAGE_BITS) )) )

BOOT_SIZE      := 0x00000200
VECTORS_BASE   := 0x00000000
VECTORS_SIZE   := $(shell echo $$(( 0x00004000 - $(BOOT_SIZE) )) )
VECTORS_END    := $(shell echo $$(( $(VECTORS_BASE) + $(VECTORS_SIZE) )) )
BIOS_BASE      := 0x05800000
BIOS_SIZE      := $(shell echo $$(( $(BIOS_IMAGE_SIZE) - $(BOOT_SIZE) - $(VECTORS_SIZE) )) )
BIOS_END       := $(shell echo $$(( $(BIOS_BASE) + $(BIOS_SIZE) )) )

LOAD_IMAGE_BASE:= 0x04000000

# boot.bin build options
boot.o_CFLAGS:= -DBOOT_SIZE=$(BOOT_SIZE)
boot.o_CFLAGS+= -DVECTORS_BASE=$(VECTORS_BASE) -DVECTORS_SIZE=$(VECTORS_SIZE)
boot.o_CFLAGS+= -DBIOS_IMAGE_BITS=$(BIOS_IMAGE_BITS)
boot.out_LDFLAGS+= -T $(SRCDIR)/boot.ld
# vectors.bin build options
vectors.o_CFLAGS:= -DBIOS_BASE=$(BIOS_BASE) -DBIOS_SIZE=$(BIOS_SIZE)
vectors.out_LDFLAGS+= -T $(SRCDIR)/vectors.ld
vectors.bin_OPTIONS:= --pad-to $(VECTORS_END)
# main.bin build options
main.o_CFLAGS:= -DLOAD_IMAGE_BASE=$(LOAD_IMAGE_BASE)
main.out_LDFLAGS:= -T $(SRCDIR)/main.ld
main.out_OBJS:= main.o bootinfos.o bloc.o pci.o of.o start.o nvram.o vga.o mm.o char.o
main.out_OBJS:= $(addprefix $(OBJDIR)/, $(main.out_OBJS))
# Pseudo-libc objects
FORMAT_FUNCS:= _vprintf printf sprintf snprintf vprintf vsprintf vsnprintf
FORMAT_FUNCS+= dprintf vdprintf
MEM_FUNCS:= memcpy memccpy mempcpy memmove memcmove mempmove
MEM_FUNCS+= memset memcmp memchr rawmemchr memrchr memmem
STR_FUNCS:= strcpy strdup strndup stpcpy stpncpy strcat strncat
STR_FUNCS+= strcmp strcasecmp strncmp strncasecmp strchr strchrnul strrchr
STR_FUNCS+= basename dirname
STR_FUNCS+= strlen strnlen
MODULES:= format mem str
format_OBJS:=$(addsuffix .o, $(FORMAT_FUNCS))
mem_OBJS:=$(addsuffix .o, $(MEM_FUNCS))
str_OBJS:=$(addsuffix .o, $(STR_FUNCS))
pseudo_libc_OBJS:= malloc.o errno.o $(format_OBJS) $(mem_OBJS) $(str_OBJS)
#pseudo_libc_OBJS:= errno.o $(format_OBJS) $(mem_OBJS) $(str_OBJS)
main.out_OBJS+= $(addprefix $(OBJDIR)/, $(pseudo_libc_OBJS))
# libexec objects
libexec_OBJS:= core.o elf.o xcoff.o macho.o chrp.o prep.o pef.o
main.out_OBJS+= $(addprefix $(OBJDIR)/exec_, $(libexec_OBJS))
# libfs objects
libfs_OBJS:= core.o raw.o ext2.o isofs.o hfs.o
main.out_OBJS+= $(addprefix $(OBJDIR)/fs_, $(libfs_OBJS))
# libpart objects
libpart_OBJS:= core.o apple.o isofs.o prep.o
main.out_OBJS+= $(addprefix $(OBJDIR)/part_, $(libpart_OBJS))
# char devices drivers
chardev_OBJS:= pckbd.o kbdadb.o kbd.o
# bloc devices drivers
blocdev_OBJS:=
# devices drivers
dev_OBJS:= $(addprefix bloc_, $(blocdev_OBJS))
dev_OBJS+= $(addprefix char_, $(chardev_OBJS))
main.out_OBJS+= $(addprefix $(OBJDIR)/dev_, $(dev_OBJS))

CUR= $(notdir $@)
CFLAGS+= $($(CUR)_CFLAGS)
LDFLAGS+= $($(CUR)_LDFLAGS)

BIN_TARGETS:= $(OBJDIR)/vectors.bin $(OBJDIR)/main.bin $(OBJDIR)/boot.bin
TARGET:= ppc_rom.bin
main.bin_OPTIONS:= --gap-fill 0xFF --pad-to $(BIOS_END)

CURDIR:= $(shell basename `pwd`)
SOURCES:= boot.S vectors.S start.S main.c of.c
SOURCES+= vga.c vgafont.h bootinfos.c nvram.c file.c fs.c part.c bloc.c pci.c bios.h
LD_SCRIPTS:= boot.ld vectors.ld main.ld
MISC_FILES:= Makefile COPYING README Changelog Timestamp
SVN_DIRS:= $(shell find . -type d -name .svn)
TARBALL:= OpenHackWare.tar.bz2
TARFILES:= $(addprefix $(SRCDIR)/, $(SOURCES) $(LD_SCRIPTS)) $(MISC_FILES)
SVN_TARBALL:= OpenHackWare_svn.tar.bz2
DISTFILE:= OpenHackWare_bin.tar.bz2

#all: print
all: $(OBJDIR) $(DISTDIR) $(addprefix $(DISTDIR)/, $(TARGET))

dist: all $(CURDIR)/Timestamp
	cd $(DISTDIR) && $(TAR) -cjf $(DISTFILE) $(DISTDIR)/$(TARGET) Timestamp

print:
	@$(DEBUG) "BOOT_SIZE    = $(BOOT_SIZE)"
	@$(DEBUG) "VECTORS_BASE = $(VECTORS_BASE)"
	@$(DEBUG) "VECTORS_SIZE = $(VECTORS_SIZE)"
	@$(DEBUG) "VECTORS_END  = $(VECTORS_END)"
	@$(DEBUG) "BIOS_BASE    = $(BIOS_BASE)"
	@$(DEBUG) "BIOS_SIZE    = $(BIOS_SIZE)"
	@$(DEBUG) "BIOS_END     = $(BIOS_END)"

$(OBJDIR) $(DISTDIR):
	@$(MKDIR) $@

$(DISTDIR)/$(TARGET): $(BIN_TARGETS)
	$(CAT) $^ > $@

$(OBJDIR)/%.bin: $(OBJDIR)/%.out
	$(OBJCOPY) -O binary $($(notdir $@)_OPTIONS) $< $@

$(OBJDIR)/%.out: $(OBJDIR)/%.o $(SRCDIR)/%.ld
	$(LD) $(LDFLAGS) -o $@ $<

$(OBJDIR)/main.out: $(main.out_OBJS) $(SRCDIR)/main.ld
	$(LD) $(LDFLAGS) -o $@ $(main.out_OBJS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/bios.h
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -o $@ $<

$(OBJDIR)/%.o: $(SRCDIR)/%.S $(SRCDIR)/bios.h
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -Wa,-mregnames -o $@ $<

	$(CC) $(CFLAGS) -D__USE_$(subst .o,,$(@F))__ -c -o $@ $<

# Pseudo libc objects
$(OBJDIR)/%.o: $(SRCDIR)/libc/src/%.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -o $@ $<

$(OBJDIR)/mem%.o: $(SRCDIR)/libc/src/mem.c
	$(CC) $(CFLAGS) -D__USE_$(subst .o,,$(@F))__ -c -o $@ $<

$(OBJDIR)/rawmemchr.o: $(SRCDIR)/libc/src/mem.c
	$(CC) $(CFLAGS) -D__USE_$(subst .o,,$(@F))__ -c -o $@ $<

$(OBJDIR)/str%.o: $(SRCDIR)/libc/src/str.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) $(CFLAGS) -D__USE_$(subst .o,,$(@F))__ -c -o $@ $<

$(OBJDIR)/stp%.o: $(SRCDIR)/libc/src/str.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) $(CFLAGS) -D__USE_$(subst .o,,$(@F))__ -c -o $@ $<

$(OBJDIR)/basename.o: $(SRCDIR)/libc/src/str.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) $(CFLAGS) -D__USE_$(subst .o,,$(@F))__ -c -o $@ $<

$(OBJDIR)/dirname.o: $(SRCDIR)/libc/src/str.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) $(CFLAGS) -D__USE_$(subst .o,,$(@F))__ -c -o $@ $<

$(OBJDIR)/%rintf.o: $(SRCDIR)/libc/src/format.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) $(CFLAGS) -D__USE_$(subst .o,,$(@F))__ -c -o $@ $<

# libexec objects
$(OBJDIR)/exec_%.o: $(SRCDIR)/libexec/%.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -o $@ $<

# libfs objects
$(OBJDIR)/fs_%.o: $(SRCDIR)/libfs/%.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -o $@ $<

# libpart objects
$(OBJDIR)/part_%.o: $(SRCDIR)/libpart/%.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -o $@ $<

# Devices drivers
$(OBJDIR)/dev_%.o: $(SRCDIR)/dev/%.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -o $@ $<
# Char devices drivers
$(OBJDIR)/dev_char_%.o: $(SRCDIR)/dev/char/%.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -o $@ $<
# Bloc devices drivers
$(OBJDIR)/dev_bloc_%.o: $(SRCDIR)/dev/bloc/%.c
	@$(DEBUG) "CFLAGS  = $(CFLAGS)"
	$(CC) -c $(CFLAGS) -o $@ $<

# Other targets
tarball: $(CURDIR)/Timestamp
	cd .. && $(TAR) -cjf $(CURDIR)/$(TARBALL) \
                             $(addprefix $(CURDIR)/, $(TARFILES))

svntarball: $(CURDIR)/Timestamp
	cd .. && $(TAR) -cjf $(CURDIR)/$(SVN_TARBALL) \
                             $(addprefix $(CURDIR)/, $(TARFILES) $(SVN_DIRS))

$(CURDIR)/Timestamp: force
	@cd .. && echo "$(BUILD_DATE) at $(BUILD_TIME)" > $@

clean:
	$(RM) $(OBJDIR) $(addprefix $(DISTDIR)/, $(TARGETS))
	$(RM) $(DISTFILE) $(CURDIR)/$(TARBALL)

cleansrc: clean
	$(RM) *~ src/*~ .*~ src/.*~

# Keep all intermediary files
.PRECIOUS: $(OBJDIR)/%.o $(OBJDIR)/%.out

.PHONY: all dist print tarball clean cleansrc

force:
