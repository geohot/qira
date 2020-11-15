# SeaBIOS build system
#
# Copyright (C) 2008-2012  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU LGPLv3 license.

# Output directory
OUT=out/

# Common command definitions
export HOSTCC             := $(CC)
export CONFIG_SHELL       := sh
export KCONFIG_AUTOHEADER := autoconf.h
export KCONFIG_CONFIG     := $(CURDIR)/.config
export LC_ALL             := C
CROSS_PREFIX=
ifneq ($(CROSS_PREFIX),)
CC=$(CROSS_PREFIX)gcc
endif
AS=$(CROSS_PREFIX)as
LD=$(CROSS_PREFIX)ld
OBJCOPY=$(CROSS_PREFIX)objcopy
OBJDUMP=$(CROSS_PREFIX)objdump
STRIP=$(CROSS_PREFIX)strip
PYTHON=python
CPP=cpp
IASL:=iasl
LD32BIT_FLAG:=-melf_i386

# Source files
SRCBOTH=misc.c stacks.c output.c string.c block.c cdrom.c disk.c mouse.c kbd.c \
    system.c serial.c clock.c resume.c pnpbios.c vgahooks.c pcibios.c apm.c \
    hw/pci.c hw/timer.c hw/rtc.c hw/dma.c hw/pic.c hw/ps2port.c hw/serialio.c \
    hw/usb.c hw/usb-uhci.c hw/usb-ohci.c hw/usb-ehci.c \
    hw/usb-hid.c hw/usb-msc.c hw/usb-uas.c \
    hw/blockcmd.c hw/floppy.c hw/ata.c hw/ramdisk.c \
    hw/virtio-ring.c hw/virtio-pci.c hw/virtio-blk.c hw/virtio-scsi.c \
    hw/lsi-scsi.c hw/esp-scsi.c hw/megasas.c
SRC16=$(SRCBOTH)
SRC32FLAT=$(SRCBOTH) post.c memmap.c malloc.c romfile.c x86.c optionroms.c \
    pmm.c font.c boot.c bootsplash.c jpeg.c bmp.c \
    hw/ahci.c hw/pvscsi.c hw/usb-xhci.c hw/usb-hub.c hw/sdcard.c \
    fw/coreboot.c fw/lzmadecode.c fw/csm.c fw/biostables.c \
    fw/paravirt.c fw/shadow.c fw/pciinit.c fw/smm.c fw/smp.c fw/mtrr.c fw/xen.c \
    fw/acpi.c fw/mptable.c fw/pirtable.c fw/smbios.c fw/romfile_loader.c
SRC32SEG=string.c output.c pcibios.c apm.c stacks.c hw/pci.c hw/serialio.c
DIRS=src src/hw src/fw vgasrc

# Default compiler flags
cc-option=$(shell if test -z "`$(1) $(2) -S -o /dev/null -xc /dev/null 2>&1`" \
    ; then echo "$(2)"; else echo "$(3)"; fi ;)

CPPFLAGS = -P -MD -MT $@

COMMONCFLAGS := -I$(OUT) -Isrc -Os -MD -g \
    -Wall -Wno-strict-aliasing -Wold-style-definition \
    $(call cc-option,$(CC),-Wtype-limits,) \
    -m32 -march=i386 -mregparm=3 -mpreferred-stack-boundary=2 \
    -minline-all-stringops -fomit-frame-pointer \
    -freg-struct-return -ffreestanding -fno-delete-null-pointer-checks \
    -ffunction-sections -fdata-sections -fno-common -fno-merge-constants
COMMONCFLAGS += $(call cc-option,$(CC),-nopie,)
COMMONCFLAGS += $(call cc-option,$(CC),-fno-stack-protector,)
COMMONCFLAGS += $(call cc-option,$(CC),-fno-stack-protector-all,)
COMMA := ,

CFLAGS32FLAT := $(COMMONCFLAGS) -DMODE16=0 -DMODESEGMENT=0
CFLAGSSEG := $(COMMONCFLAGS) -DMODESEGMENT=1 -fno-defer-pop \
    $(call cc-option,$(CC),-fno-jump-tables,-DMANUAL_NO_JUMP_TABLE) \
    $(call cc-option,$(CC),-fno-tree-switch-conversion,)
CFLAGS32SEG := $(CFLAGSSEG) -DMODE16=0
CFLAGS16 := $(CFLAGSSEG) -DMODE16=1 \
    $(call cc-option,$(CC),-m16,-Wa$(COMMA)src/code16gcc.s) \
    $(call cc-option,$(CC),--param large-stack-frame=4,-fno-inline)

# Run with "make V=1" to see the actual compile commands
ifdef V
Q=
else
Q=@
MAKEFLAGS += --no-print-directory
endif

# Default targets
-include $(KCONFIG_CONFIG)

target-y :=
target-$(CONFIG_QEMU) += $(OUT)bios.bin
target-$(CONFIG_CSM) += $(OUT)Csm16.bin
target-$(CONFIG_COREBOOT) += $(OUT)bios.bin.elf
target-$(CONFIG_BUILD_VGABIOS) += $(OUT)vgabios.bin

all: $(target-y)

# Make definitions
.PHONY : all clean distclean FORCE
.DELETE_ON_ERROR:


################ Common build rules

# Verify the build environment works.
TESTGCC:=$(shell OUT="$(OUT)" CC="$(CC)" LD="$(LD)" IASL="$(IASL)" scripts/test-build.sh)
ifeq "$(TESTGCC)" "-1"
$(error "Please upgrade the build environment")
endif

ifeq "$(TESTGCC)" "0"
# Use -fwhole-program
CFLAGSWHOLE=-fwhole-program -DWHOLE_PROGRAM
endif

# Do a whole file compile by textually including all C code.
define whole-compile
@echo "  Compiling whole program $3"
$(Q)printf '$(foreach i,$2,#include "$i"\n)' > $3.tmp.c
$(Q)$(CC) -I. $1 $(CFLAGSWHOLE) -c $3.tmp.c -o $3
endef

%.strip.o: %.o
	@echo "  Stripping $@"
	$(Q)$(STRIP) $< -o $@

$(OUT)%.s: %.c
	@echo "  Compiling to assembler $@"
	$(Q)$(CC) $(CFLAGS16) -S -c $< -o $@

$(OUT)%.o: %.c $(OUT)autoconf.h
	@echo "  Compile checking $@"
	$(Q)$(CC) $(CFLAGS32FLAT) -c $< -o $@

$(OUT)%.lds: %.lds.S
	@echo "  Precompiling $@"
	$(Q)$(CPP) $(CPPFLAGS) -D__ASSEMBLY__ $< -o $@


################ Main BIOS build rules

$(OUT)asm-offsets.s: $(OUT)autoconf.h

$(OUT)asm-offsets.h: $(OUT)src/asm-offsets.s
	@echo "  Generating offset file $@"
	$(Q)./scripts/gen-offsets.sh $< $@

$(OUT)ccode16.o: $(OUT)autoconf.h $(patsubst %.c, $(OUT)src/%.o,$(SRC16)) ; $(call whole-compile, $(CFLAGS16), $(addprefix src/, $(SRC16)),$@)

$(OUT)code32seg.o: $(OUT)autoconf.h $(patsubst %.c, $(OUT)src/%.o,$(SRC32SEG)) ; $(call whole-compile, $(CFLAGS32SEG), $(addprefix src/, $(SRC32SEG)),$@)

$(OUT)ccode32flat.o: $(OUT)autoconf.h $(patsubst %.c, $(OUT)src/%.o,$(SRC32FLAT)) ; $(call whole-compile, $(CFLAGS32FLAT), $(addprefix src/, $(SRC32FLAT)),$@)

$(OUT)romlayout.o: src/romlayout.S $(OUT)autoconf.h $(OUT)asm-offsets.h
	@echo "  Compiling (16bit) $@"
	$(Q)$(CC) $(CFLAGS16) -c -D__ASSEMBLY__ $< -o $@

$(OUT)romlayout16.lds: $(OUT)ccode32flat.o $(OUT)code32seg.o $(OUT)ccode16.o $(OUT)romlayout.o scripts/layoutrom.py scripts/buildversion.sh
	@echo "  Building ld scripts"
	$(Q)BUILD_VERSION="$(VERSION)" ./scripts/buildversion.sh $(OUT)version.c
	$(Q)$(CC) $(CFLAGS32FLAT) -c $(OUT)version.c -o $(OUT)version.o
	$(Q)$(LD) $(LD32BIT_FLAG) -r $(OUT)ccode32flat.o $(OUT)version.o -o $(OUT)code32flat.o
	$(Q)$(LD) $(LD32BIT_FLAG) -r $(OUT)ccode16.o $(OUT)romlayout.o -o $(OUT)code16.o
	$(Q)$(OBJDUMP) -thr $(OUT)code32flat.o > $(OUT)code32flat.o.objdump
	$(Q)$(OBJDUMP) -thr $(OUT)code32seg.o > $(OUT)code32seg.o.objdump
	$(Q)$(OBJDUMP) -thr $(OUT)code16.o > $(OUT)code16.o.objdump
	$(Q)$(PYTHON) ./scripts/layoutrom.py $(OUT)code16.o.objdump $(OUT)code32seg.o.objdump $(OUT)code32flat.o.objdump $(OUT)$(KCONFIG_AUTOHEADER) $(OUT)romlayout16.lds $(OUT)romlayout32seg.lds $(OUT)romlayout32flat.lds

# These are actually built by scripts/layoutrom.py above, but by pulling them
# into an extra rule we prevent make -j from spawning layoutrom.py 4 times.
$(OUT)romlayout32seg.lds $(OUT)romlayout32flat.lds $(OUT)code32flat.o $(OUT)code16.o: $(OUT)romlayout16.lds

$(OUT)rom16.o: $(OUT)code16.o $(OUT)romlayout16.lds
	@echo "  Linking $@"
	$(Q)$(LD) -T $(OUT)romlayout16.lds $< -o $@

$(OUT)rom32seg.o: $(OUT)code32seg.o $(OUT)romlayout32seg.lds
	@echo "  Linking $@"
	$(Q)$(LD) -T $(OUT)romlayout32seg.lds $< -o $@

$(OUT)rom.o: $(OUT)rom16.strip.o $(OUT)rom32seg.strip.o $(OUT)code32flat.o $(OUT)romlayout32flat.lds
	@echo "  Linking $@"
	$(Q)$(LD) -T $(OUT)romlayout32flat.lds $(OUT)rom16.strip.o $(OUT)rom32seg.strip.o $(OUT)code32flat.o -o $@

$(OUT)bios.bin.prep: $(OUT)rom.o scripts/checkrom.py
	@echo "  Prepping $@"
	$(Q)rm -f $(OUT)bios.bin $(OUT)Csm16.bin $(OUT)bios.bin.elf
	$(Q)$(OBJDUMP) -thr $< > $<.objdump
	$(Q)$(OBJCOPY) -O binary $< $(OUT)bios.bin.raw
	$(Q)$(PYTHON) ./scripts/checkrom.py $<.objdump $(CONFIG_ROM_SIZE) $(OUT)bios.bin.raw $(OUT)bios.bin.prep

$(OUT)bios.bin: $(OUT)bios.bin.prep
	@echo "  Creating $@"
	$(Q)cp $< $@

$(OUT)Csm16.bin: $(OUT)bios.bin.prep
	@echo "  Creating $@"
	$(Q)cp $< $@

$(OUT)bios.bin.elf: $(OUT)rom.o $(OUT)bios.bin.prep
	@echo "  Creating $@"
	$(Q)$(STRIP) -R .comment $< -o $(OUT)bios.bin.elf


################ VGA build rules

# VGA src files
SRCVGA=src/output.c src/string.c src/hw/pci.c src/hw/serialio.c \
    vgasrc/vgainit.c vgasrc/vgabios.c vgasrc/vgafb.c \
    vgasrc/vgafonts.c vgasrc/vbe.c \
    vgasrc/stdvga.c vgasrc/stdvgamodes.c vgasrc/stdvgaio.c \
    vgasrc/clext.c vgasrc/bochsvga.c vgasrc/geodevga.c \
    src/fw/coreboot.c vgasrc/cbvga.c

ifeq "$(CONFIG_VGA_FIXUP_ASM)" "y"
$(OUT)vgaccode16.raw.s: $(OUT)autoconf.h $(patsubst %.c, $(OUT)%.o,$(SRCVGA)) ; $(call whole-compile, $(filter-out -fomit-frame-pointer,$(CFLAGS16)) -fno-omit-frame-pointer -S -Isrc, $(SRCVGA),$@)

$(OUT)vgaccode16.o: $(OUT)vgaccode16.raw.s scripts/vgafixup.py
	@echo "  Fixup VGA rom assembler"
	$(Q)$(PYTHON) ./scripts/vgafixup.py $< $(OUT)vgaccode16.s
	$(Q)$(AS) --32 src/code16gcc.s $(OUT)vgaccode16.s -o $@
else
$(OUT)vgaccode16.o: $(OUT)autoconf.h $(patsubst %.c, $(OUT)%.o,$(SRCVGA)) ; $(call whole-compile, $(CFLAGS16) -Isrc, $(SRCVGA),$@)
endif

$(OUT)vgaentry.o: vgasrc/vgaentry.S $(OUT)autoconf.h $(OUT)asm-offsets.h
	@echo "  Compiling (16bit) $@"
	$(Q)$(CC) $(CFLAGS16) -c -D__ASSEMBLY__ $< -o $@

$(OUT)vgarom.o: $(OUT)vgaccode16.o $(OUT)vgaentry.o $(OUT)vgasrc/vgalayout.lds scripts/buildversion.sh
	@echo "  Linking $@"
	$(Q)BUILD_VERSION="$(VERSION)" ./scripts/buildversion.sh $(OUT)vgaversion.c VAR16
	$(Q)$(CC) $(CFLAGS16) -c $(OUT)vgaversion.c -o $(OUT)vgaversion.o
	$(Q)$(LD) --gc-sections -T $(OUT)vgasrc/vgalayout.lds $(OUT)vgaccode16.o $(OUT)vgaentry.o $(OUT)vgaversion.o -o $@

$(OUT)vgabios.bin.raw: $(OUT)vgarom.o
	@echo "  Extracting binary $@"
	$(Q)$(OBJCOPY) -O binary $< $@

$(OUT)vgabios.bin: $(OUT)vgabios.bin.raw scripts/buildrom.py
	@echo "  Finalizing rom $@"
	$(Q)$(PYTHON) ./scripts/buildrom.py $< $@


################ DSDT build rules

iasl-option=$(shell if test -z "`$(1) $(2) 2>&1 > /dev/null`" \
    ; then echo "$(2)"; else echo "$(3)"; fi ;)

$(OUT)%.hex: %.dsl ./scripts/acpi_extract_preprocess.py ./scripts/acpi_extract.py
	@echo "  Compiling IASL $@"
	$(Q)$(CPP) $(CPPFLAGS) $< -o $(OUT)$*.dsl.i.orig
	$(Q)$(PYTHON) ./scripts/acpi_extract_preprocess.py $(OUT)$*.dsl.i.orig > $(OUT)$*.dsl.i
	$(Q)$(IASL) $(call iasl-option,$(IASL),-Pn,) -vs -l -tc -p $(OUT)$* $(OUT)$*.dsl.i
	$(Q)$(PYTHON) ./scripts/acpi_extract.py $(OUT)$*.lst > $(OUT)$*.off
	$(Q)cat $(OUT)$*.off > $@

$(OUT)src/fw/acpi.o: $(OUT)src/fw/acpi-dsdt.hex $(OUT)src/fw/ssdt-proc.hex $(OUT)src/fw/ssdt-pcihp.hex $(OUT)src/fw/ssdt-misc.hex $(OUT)src/fw/q35-acpi-dsdt.hex

################ Kconfig rules

define do-kconfig
$(Q)mkdir -p $(OUT)/scripts/kconfig/lxdialog
$(Q)mkdir -p $(OUT)/include/config
$(Q)mkdir -p $(addprefix $(OUT), $(DIRS))
$(Q)$(MAKE) -C $(OUT) -f $(CURDIR)/scripts/kconfig/Makefile srctree=$(CURDIR) src=scripts/kconfig obj=scripts/kconfig Q=$(Q) Kconfig=$(CURDIR)/src/Kconfig $1
endef

$(OUT)autoconf.h : $(KCONFIG_CONFIG) ; $(call do-kconfig, silentoldconfig)
$(KCONFIG_CONFIG): src/Kconfig vgasrc/Kconfig ; $(call do-kconfig, olddefconfig)
%onfig: ; $(call do-kconfig, $@)
help: ; $(call do-kconfig, $@)


################ Generic rules

clean:
	$(Q)rm -rf $(OUT)

distclean: clean
	$(Q)rm -f .config .config.old

-include $(patsubst %,$(OUT)%/*.d,$(DIRS))
