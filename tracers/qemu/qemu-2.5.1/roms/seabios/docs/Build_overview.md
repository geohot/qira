The SeaBIOS code can be built using standard GNU tools. A recent Linux
distribution should be able to build SeaBIOS using the standard
compiler tools.

Building SeaBIOS
================

First, [obtain the code](Download). SeaBIOS can be compiled for
several different build targets. It is also possible to configure
additional compile time options - run **make menuconfig** to do this.

Build for QEMU (along with KVM, Xen, and Bochs)
-----------------------------------------------

To build for QEMU (and similar), one should be able to run "make" in
the main directory. The resulting file "out/bios.bin" contains the
processed bios image.

One can use the resulting binary with QEMU by using QEMU's "-bios"
option. For example:

`qemu -bios out/bios.bin -fda myfdimage.img`

One can also use the resulting binary with Bochs. For example:

`bochs -q 'floppya: 1_44=myfdimage.img' 'romimage: file=out/bios.bin'`

Build for coreboot
------------------

To build for coreboot please see the coreboot build instructions at:
<http://www.coreboot.org/SeaBIOS>

Build as a UEFI Compatibility Support Module (CSM)
--------------------------------------------------

To build as a CSM, first run kconfig (make menuconfig) and enable
CONFIG_CSM. Then build SeaBIOS (make) - the resulting binary will be
in "out/Csm16.bin".

This binary may be used with the OMVF/EDK-II UEFI firmware. It will
provide "legacy" BIOS services for booting non-EFI operating systems
and will also allow OVMF to display on otherwise unsupported video
hardware by using the traditional VGA BIOS. (Windows 2008r2 is known
to use INT 10h BIOS calls even when booted via EFI, and the presence
of a CSM makes this work as expected too.)

Having built SeaBIOS with CONFIG_CSM, one should be able to drop the
result (out/Csm16.bin) into an OVMF build tree at
OvmfPkg/Csm/Csm16/Csm16.bin and then build OVMF with 'build -D
CSM_ENABLE'. The SeaBIOS binary will be included as a discrete file
within the 'Flash Volume' which is created, and there are tools which
will extract it and allow it to be replaced.

Overview of files in the repository
===================================

The **src/** directory contains the main bios source code. The
**src/hw/** directory contains source code specific to hardware
drivers. The **src/fw/** directory contains source code for platform
firmware initialization. The **src/std/** directory contains header
files describing standard bios, firmware, and hardware interfaces.

The **vgasrc/** directory contains code for VGA BIOS implementations.
This code is separate from the main BIOS code in the src/ directory.
When the build is configured to produce a VGA BIOS the resulting
binary is found in out/vgabios.bin. The VGA BIOS code is always
compiled in 16bit mode.

The **scripts/** directory contains helper utilities for manipulating
and building the final roms.

The **out/** directory is created by the build process - it contains
all intermediate and final files.

When reading the C code be aware that code that runs in 16bit mode can
not arbitrarily access non-stack memory - see [Memory Model](Memory
Model) for more details. For information on the major C code functions
and where code execution starts see [Execution and code
flow](Execution and code flow).
