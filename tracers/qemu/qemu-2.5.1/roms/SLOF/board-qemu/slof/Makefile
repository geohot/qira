# *****************************************************************************
# * Copyright (c) 2004, 2011 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/


include ../Makefile.dirs

include $(TOPBRDDIR)/config
include $(TOPCMNDIR)/make.rules

all: version.o Makefile.dep OF.ffs paflof $(SLOFCMNDIR)/xvect.bin

CPPFLAGS = -I$(LIBCMNDIR)/libbootmsg -I$(LIBCMNDIR)/libhvcall \
	   -I$(LIBCMNDIR)/libvirtio -I$(LIBCMNDIR)/libnvram \
	   -I$(LIBCMNDIR)/libusb -I$(LIBCMNDIR)/libveth \
	   -I$(LIBCMNDIR)/libe1k
SLOF_LIBS = \
	$(LIBCMNDIR)/libbootmsg.a \
	$(LIBCMNDIR)/libelf.a \
	$(LIBCMNDIR)/libhvcall.a \
	$(LIBCMNDIR)/libvirtio.a \
	$(LIBCMNDIR)/libusb.a \
	$(LIBCMNDIR)/libnvram.a \
	$(LIBCMNDIR)/libveth.a \
	$(LIBCMNDIR)/libe1k.a
BOARD_SLOF_IN = \
	$(LIBCMNDIR)/libhvcall/hvcall.in \
	$(LIBCMNDIR)/libvirtio/virtio.in \
	$(LIBCMNDIR)/libusb/usb.in \
	$(LIBCMNDIR)/libbootmsg/bootmsg.in \
	$(LIBCMNDIR)/libelf/libelf.in \
	$(LIBCMNDIR)/libnvram/libnvram.in \
	$(LIBCMNDIR)/libbases/libbases.in \
	$(LIBCMNDIR)/libveth/veth.in \
	$(LIBCMNDIR)/libe1k/e1k.in
BOARD_SLOF_CODE = $(BOARD_SLOF_IN:%.in=%.code)

include $(SLOFCMNDIR)/Makefile.inc

AS1FLAGS  = $(CPPFLAGS) $(RELEASE) $(FLAG) $(CPUARCHDEF)  -Wa,-mregnames

%.o: %.S
	$(CC) $(AS1FLAGS) -o $@ -c $^

FPPINCLUDES = -I. -I$(SLOFCMNDIR)/fs -I$(SLOFCMNDIR)

USB_FFS_FILES = \
	$(SLOFCMNDIR)/fs/devices/pci-class_02.fs \
	$(SLOFCMNDIR)/fs/devices/pci-class_0c.fs \
	$(SLOFCMNDIR)/fs/usb/dev-hci.fs \
	$(SLOFCMNDIR)/fs/usb/slofdev.fs \
	$(SLOFCMNDIR)/fs/usb/dev-parent-calls.fs \
	$(SLOFCMNDIR)/fs/usb/dev-keyb.fs \
	$(SLOFCMNDIR)/fs/usb/dev-mouse.fs \
	$(SLOFCMNDIR)/fs/usb/dev-storage.fs \
	$(SLOFCMNDIR)/fs/usb/dev-hub.fs


VIO_FFS_FILES = \
	$(SLOFBRDDIR)/pci-device_1af4_1000.fs \
	$(SLOFBRDDIR)/pci-device_1af4_1001.fs \
	$(SLOFBRDDIR)/pci-device_1af4_1004.fs \
	$(SLOFBRDDIR)/pci-device_1af4_1009.fs \
	$(SLOFBRDDIR)/pci-device_1af4_1050.fs \
	$(SLOFBRDDIR)/vio-hvterm.fs \
	$(SLOFBRDDIR)/vio-vscsi.fs \
	$(SLOFBRDDIR)/vio-veth.fs \
	$(SLOFBRDDIR)/rtas-nvram.fs \
	$(SLOFBRDDIR)/virtio-net.fs \
	$(SLOFBRDDIR)/virtio-block.fs \
	$(SLOFBRDDIR)/virtio-fs.fs \
	$(SLOFBRDDIR)/dev-null.fs \
	$(SLOFBRDDIR)/virtio-scsi.fs

# Files that should go into the ROM fs (and so have to be listed in OF.ffs):
OF_FFS_FILES = \
	$(SLOFCMNDIR)/fs/ide.fs \
	$(SLOFCMNDIR)/fs/fbuffer.fs \
	$(SLOFCMNDIR)/fs/graphics.fs \
	$(SLOFCMNDIR)/fs/generic-disk.fs \
	$(SLOFCMNDIR)/fs/dma-function.fs \
	$(SLOFCMNDIR)/fs/pci-device.fs \
	$(SLOFCMNDIR)/fs/pci-bridge.fs \
	$(SLOFCMNDIR)/fs/pci-properties.fs \
	$(SLOFCMNDIR)/fs/pci-config-bridge.fs \
	$(SLOFCMNDIR)/fs/update_flash.fs \
	$(SLOFCMNDIR)/fs/xmodem.fs \
	$(SLOFCMNDIR)/fs/scsi-disk.fs \
	$(SLOFCMNDIR)/fs/scsi-host-helpers.fs \
	$(SLOFCMNDIR)/fs/scsi-probe-helpers.fs \
	$(SLOFCMNDIR)/fs/scsi-support.fs \
	$(SLOFBRDDIR)/default-font.bin \
	$(SLOFBRDDIR)/pci-phb.fs \
	$(SLOFBRDDIR)/rtas.fs \
	$(SLOFBRDDIR)/pci-device_1234_1111.fs \
	$(SLOFBRDDIR)/pci-device_1013_00b8.fs \
	$(SLOFBRDDIR)/pci-device_8086_100e.fs \
	$(SLOFBRDDIR)/e1k.fs \
	$(SLOFBRDDIR)/qemu-vga.fs \
	$(FCODE_FFS_FILES)

# Uncomment the following line to enable the USB code:
OF_FFS_FILES += $(USB_FFS_FILES)

OF_FFS_FILES += $(VIO_FFS_FILES)

OF_FFS_FILES := $(OF_FFS_FILES:%.fs=%.fsi)

OF.ffs: Makefile $(SLOFCMNDIR)/Makefile.inc $(OF_FFS_FILES)
	$(MAKE) create_OF_ffs

# Rules for cleaning up:
.PHONY: clean_here clean distclean

clean_here:
	rm -f *.o OF.fsi OF.ffs

clean: clean_here clean_slof

distclean: clean_here distclean_slof
