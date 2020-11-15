SHELL = /bin/sh

CC      = gcc
CFLAGS  = -g -O2 -Wall -Wstrict-prototypes
LDFLAGS = 

GCC = gcc
BCC = bcc
AS86 = as86

RELEASE = `pwd | sed "s-.*/--"`
RELDATE = `date '+%d %b %Y'`
RELVERS = `pwd | sed "s-.*/--" | sed "s/vgabios//" | sed "s/-//"`

VGABIOS_DATE = "-DVGABIOS_DATE=\"$(RELDATE)\""

all: bios cirrus-bios stdvga-bios vmware-bios qxl-bios

bios: vgabios.bin vgabios.debug.bin

cirrus-bios: vgabios-cirrus.bin vgabios-cirrus.debug.bin

stdvga-bios: vgabios-stdvga.bin vgabios-stdvga.debug.bin

vmware-bios: vgabios-vmware.bin vgabios-vmware.debug.bin

qxl-bios: vgabios-qxl.bin vgabios-qxl.debug.bin

clean:
	/bin/rm -f  biossums vbetables-gen vbetables.h *.o *.s *.ld86 \
          temp.awk.* vgabios*.orig _vgabios_* _vgabios-debug_* core vgabios*.bin vgabios*.txt $(RELEASE).bin *.bak

dist-clean: clean

# source files
VGA_FILES := vgabios.c vgabios.h vgafonts.h vgatables.h
VBE_FILES := vbe.h vbe.c vbetables.h

# build flags
vgabios.bin              : VGAFLAGS := -DVBE -DPCI_VID=0x1234
vgabios.debug.bin        : VGAFLAGS := -DVBE -DPCI_VID=0x1234 -DDEBUG
vgabios-cirrus.bin       : VGAFLAGS := -DCIRRUS -DPCIBIOS 
vgabios-cirrus.debug.bin : VGAFLAGS := -DCIRRUS -DPCIBIOS -DCIRRUS_DEBUG
vgabios-stdvga.bin       : VGAFLAGS := -DVBE -DPCIBIOS -DPCI_VID=0x1234 -DPCI_DID=0x1111
vgabios-stdvga.debug.bin : VGAFLAGS := -DVBE -DPCIBIOS -DPCI_VID=0x1234 -DPCI_DID=0x1111 -DDEBUG
vgabios-vmware.bin       : VGAFLAGS := -DVBE -DPCIBIOS -DPCI_VID=0x15ad -DPCI_DID=0x0405
vgabios-vmware.debug.bin : VGAFLAGS := -DVBE -DPCIBIOS -DPCI_VID=0x15ad -DPCI_DID=0x0405 -DDEBUG
vgabios-qxl.bin          : VGAFLAGS := -DVBE -DPCIBIOS -DPCI_VID=0x1b36 -DPCI_DID=0x0100
vgabios-qxl.debug.bin    : VGAFLAGS := -DVBE -DPCIBIOS -DPCI_VID=0x1b36 -DPCI_DID=0x0100 -DDEBUG

# dist names
vgabios.bin              : DISTNAME := VGABIOS-lgpl-latest.bin
vgabios.debug.bin        : DISTNAME := VGABIOS-lgpl-latest.debug.bin
vgabios-cirrus.bin       : DISTNAME := VGABIOS-lgpl-latest.cirrus.bin
vgabios-cirrus.debug.bin : DISTNAME := VGABIOS-lgpl-latest.cirrus.debug.bin
vgabios-stdvga.bin       : DISTNAME := VGABIOS-lgpl-latest.stdvga.bin
vgabios-stdvga.debug.bin : DISTNAME := VGABIOS-lgpl-latest.stdvga.debug.bin
vgabios-vmware.bin       : DISTNAME := VGABIOS-lgpl-latest.vmware.bin
vgabios-vmware.debug.bin : DISTNAME := VGABIOS-lgpl-latest.vmware.debug.bin
vgabios-qxl.bin          : DISTNAME := VGABIOS-lgpl-latest.qxl.bin
vgabios-qxl.debug.bin    : DISTNAME := VGABIOS-lgpl-latest.qxl.debug.bin

# dependencies
vgabios.bin              : $(VGA_FILES) $(VBE_FILES) biossums
vgabios.debug.bin        : $(VGA_FILES) $(VBE_FILES) biossums
vgabios-cirrus.bin       : $(VGA_FILES) clext.c biossums
vgabios-cirrus.debug.bin : $(VGA_FILES) clext.c biossums
vgabios-stdvga.bin       : $(VGA_FILES) $(VBE_FILES) biossums
vgabios-stdvga.debug.bin : $(VGA_FILES) $(VBE_FILES) biossums
vgabios-vmware.bin       : $(VGA_FILES) $(VBE_FILES) biossums
vgabios-vmware.debug.bin : $(VGA_FILES) $(VBE_FILES) biossums
vgabios-qxl.bin          : $(VGA_FILES) $(VBE_FILES) biossums
vgabios-qxl.debug.bin    : $(VGA_FILES) $(VBE_FILES) biossums

# build rule
%.bin:
	$(GCC) -E -P vgabios.c $(VGABIOS_VERS) $(VGAFLAGS) $(VGABIOS_DATE) > _$*_.c
	$(BCC) -o $*.s -C-c -D__i86__ -S -0 _$*_.c
	sed -e 's/^\.text//' -e 's/^\.data//' $*.s > _$*_.s
	$(AS86) _$*_.s -b $*.bin -u -w- -g -0 -j -O -l $*.txt
	rm -f _$*_.s _$*_.c $*.s
	mv $*.bin $(DISTNAME)
	./biossums $(DISTNAME)
	ls -l $(DISTNAME)

release: 
	VGABIOS_VERS=\"-DVGABIOS_VERS=\\\"$(RELVERS)\\\"\" make bios cirrus-bios
	/bin/rm -f  *.o *.s *.ld86 \
          temp.awk.* vgabios.*.orig _vgabios_.*.c core *.bak .#*
	cp VGABIOS-lgpl-latest.bin ../$(RELEASE).bin
	cp VGABIOS-lgpl-latest.debug.bin ../$(RELEASE).debug.bin
	cp VGABIOS-lgpl-latest.cirrus.bin ../$(RELEASE).cirrus.bin
	cp VGABIOS-lgpl-latest.cirrus.debug.bin ../$(RELEASE).cirrus.debug.bin
	tar czvf ../$(RELEASE).tgz --exclude CVS -C .. $(RELEASE)/

biossums: biossums.c
	$(CC) -o biossums biossums.c

vbetables-gen: vbetables-gen.c
	$(CC) -o vbetables-gen vbetables-gen.c

vbetables.h: vbetables-gen
	./vbetables-gen > $@
