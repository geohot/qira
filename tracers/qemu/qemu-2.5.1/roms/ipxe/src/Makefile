###############################################################################
#
# Initialise various variables
#

CLEANUP		:=
CFLAGS		:=
ASFLAGS		:=
LDFLAGS		:=
HOST_CFLAGS	:=
MAKEDEPS	:= Makefile

###############################################################################
#
# Locations of tools
#
HOST_CC		:= gcc
RM		:= rm -f
TOUCH		:= touch
MKDIR		:= mkdir
CP		:= cp
ECHO		:= echo
PRINTF		:= printf
PERL		:= perl
TRUE		:= true
CC		:= $(CROSS_COMPILE)gcc
CPP		:= $(CC) -E
AS		:= $(CROSS_COMPILE)as
LD		:= $(CROSS_COMPILE)ld
SIZE		:= $(CROSS_COMPILE)size
AR		:= $(CROSS_COMPILE)ar
RANLIB		:= $(CROSS_COMPILE)ranlib
OBJCOPY		:= $(CROSS_COMPILE)objcopy
NM		:= $(CROSS_COMPILE)nm
OBJDUMP		:= $(CROSS_COMPILE)objdump
OPENSSL		:= openssl
CSPLIT		:= csplit
PARSEROM	:= ./util/parserom.pl
FIXROM		:= ./util/fixrom.pl
SYMCHECK	:= ./util/symcheck.pl
SORTOBJDUMP	:= ./util/sortobjdump.pl
PADIMG		:= ./util/padimg.pl
LICENCE		:= ./util/licence.pl
NRV2B		:= ./util/nrv2b
ZBIN		:= ./util/zbin
ELF2EFI32	:= ./util/elf2efi32
ELF2EFI64	:= ./util/elf2efi64
EFIROM		:= ./util/efirom
EFIFATBIN	:= ./util/efifatbin
ICCFIX		:= ./util/iccfix
EINFO		:= ./util/einfo
GENKEYMAP	:= ./util/genkeymap.pl
DOXYGEN		:= doxygen
LCAB		:= lcab
BINUTILS_DIR	:= /usr
BFD_DIR		:= $(BINUTILS_DIR)
ZLIB_DIR	:= /usr

###############################################################################
#
# SRCDIRS lists all directories containing source files.
#
SRCDIRS		:=
SRCDIRS		+= libgcc
SRCDIRS		+= core
SRCDIRS		+= net net/oncrpc net/tcp net/udp net/infiniband net/80211
SRCDIRS		+= image
SRCDIRS		+= drivers/bus
SRCDIRS		+= drivers/net
SRCDIRS		+= drivers/net/e1000
SRCDIRS		+= drivers/net/e1000e
SRCDIRS		+= drivers/net/igb
SRCDIRS		+= drivers/net/igbvf
SRCDIRS		+= drivers/net/phantom
SRCDIRS		+= drivers/net/rtl818x
SRCDIRS		+= drivers/net/ath
SRCDIRS		+= drivers/net/ath/ath5k
SRCDIRS		+= drivers/net/ath/ath9k
SRCDIRS		+= drivers/net/vxge
SRCDIRS		+= drivers/net/efi
SRCDIRS		+= drivers/net/tg3
SRCDIRS		+= drivers/block
SRCDIRS		+= drivers/nvs
SRCDIRS		+= drivers/bitbash
SRCDIRS		+= drivers/infiniband
SRCDIRS		+= drivers/usb
SRCDIRS		+= interface/pxe interface/efi interface/smbios
SRCDIRS		+= interface/bofm
SRCDIRS		+= interface/xen
SRCDIRS		+= interface/hyperv
SRCDIRS		+= tests
SRCDIRS		+= crypto crypto/mishmash
SRCDIRS		+= hci hci/commands hci/tui
SRCDIRS		+= hci/mucurses hci/mucurses/widgets
SRCDIRS		+= hci/keymap
SRCDIRS		+= usr
SRCDIRS		+= config

# NON_AUTO_SRCS lists files that are excluded from the normal
# automatic build system.
#
NON_AUTO_SRCS	:=
NON_AUTO_SRCS	+= core/version.c
NON_AUTO_SRCS	+= drivers/net/prism2.c

# INCDIRS lists the include path
#
INCDIRS		:=
INCDIRS		+= include .

###############################################################################
#
# Default build target: build the most common targets and print out a
# helpfully suggestive message
#
ALL		:= bin/blib.a bin/ipxe.dsk bin/ipxe.lkrn bin/ipxe.iso \
		   bin/ipxe.usb bin/ipxe.pxe bin/undionly.kpxe bin/rtl8139.rom \
		   bin/8086100e.mrom bin/80861209.rom bin/10500940.rom \
		   bin/10222000.rom bin/10ec8139.rom bin/1af41000.rom \
		   bin/8086100f.mrom bin/808610d3.mrom bin/15ad07b0.rom

all : $(ALL)
	@$(ECHO) '==========================================================='
	@$(ECHO)
	@$(ECHO) 'To create a bootable floppy, type'
	@$(ECHO) '    cat bin/ipxe.dsk > /dev/fd0'
	@$(ECHO) 'where /dev/fd0 is your floppy drive.  This will erase any'
	@$(ECHO) 'data already on the disk.'
	@$(ECHO)
	@$(ECHO) 'To create a bootable USB key, type'
	@$(ECHO) '    cat bin/ipxe.usb > /dev/sdX'
	@$(ECHO) 'where /dev/sdX is your USB key, and is *not* a real hard'
	@$(ECHO) 'disk on your system.  This will erase any data already on'
	@$(ECHO) 'the USB key.'
	@$(ECHO)
	@$(ECHO) 'To create a bootable CD-ROM, burn the ISO image '
	@$(ECHO) 'bin/ipxe.iso to a blank CD-ROM.'
	@$(ECHO)
	@$(ECHO) 'These images contain drivers for all supported cards.  You'
	@$(ECHO) 'can build more customised images, and ROM images, using'
	@$(ECHO) '    make bin/<rom-name>.<output-format>'
	@$(ECHO)
	@$(ECHO) '==========================================================='

###############################################################################
#
# Comprehensive build target: build a selection of cross-platform
# targets to expose potential build errors that show up only on
# certain platforms
#
everything :
	$(Q)$(MAKE) --no-print-directory $(ALL) \
		bin/3c509.rom bin/intel.rom bin/intel.mrom \
		bin-i386-efi/ipxe.efi bin-i386-efi/ipxe.efidrv \
		bin-i386-efi/ipxe.efirom \
		bin-x86_64-efi/ipxe.efi bin-x86_64-efi/ipxe.efidrv \
		bin-x86_64-efi/ipxe.efirom \
		bin-i386-linux/tap.linux bin-x86_64-linux/tap.linux \
		bin-i386-linux/tests.linux bin-x86_64-linux/tests.linux

###############################################################################
#
# VMware build target: all ROMs used with VMware
#
vmware : bin/8086100f.mrom bin/808610d3.mrom bin/10222000.rom bin/15ad07b0.rom
	@$(ECHO) '==========================================================='
	@$(ECHO) 
	@$(ECHO) 'Available ROMs:'
	@$(ECHO) '    bin/8086100f.mrom -- intel/e1000'
	@$(ECHO) '    bin/808610d3.mrom -- intel/e1000e'
	@$(ECHO) '    bin/10222000.rom  -- vlance/pcnet32'
	@$(ECHO) '    bin/15ad07b0.rom  -- vmxnet3'
	@$(ECHO) 
	@$(ECHO) 'For more information, see http://ipxe.org/howto/vmware'
	@$(ECHO)
	@$(ECHO) '==========================================================='

###############################################################################
#
# Build targets that do nothing but might be tried by users
#
configure :
	@$(ECHO) "No configuration needed."

install :
	@$(ECHO) "No installation required."

###############################################################################
#
# Version number calculations
#
VERSION_MAJOR	= 1
VERSION_MINOR	= 0
VERSION_PATCH	= 0
EXTRAVERSION	= +
MM_VERSION	= $(VERSION_MAJOR).$(VERSION_MINOR)
VERSION		= $(MM_VERSION).$(VERSION_PATCH)$(EXTRAVERSION)
ifneq ($(wildcard ../.git),)
GITVERSION := $(shell git describe --always --abbrev=1 --match "" 2>/dev/null)
VERSION		+= ($(GITVERSION))
endif
version :
	@$(ECHO) "$(VERSION)"

###############################################################################
#
# Drag in the bulk of the build system
#

MAKEDEPS	+= Makefile.housekeeping
include Makefile.housekeeping
