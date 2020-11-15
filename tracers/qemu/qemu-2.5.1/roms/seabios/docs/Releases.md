History of SeaBIOS releases. Please see [download](Download) for
information on obtaining these releases.

SeaBIOS 1.8.0
=============

Available on 20150218. Major changes in this release:

* Several USB timing fixes for USB controllers on real hardware
* Initial support for USB3 hubs
* Initial support for SD cards (on QEMU only)
* Initial support for transitioning to 32bit mode using SMIs (on QEMU
  TCG only)
* SeaVGABIOS improvements
    * Added cursor emulation to coreboot native init vgabios (cbvga)
    * Added support for read character calls when in graphics mode
* Developer documentation added to "docs/" directory in the code
  repository and several documentation updates
* Several bug fixes and code cleanups

As of the 1.8.0 release, new feature releases will modify the first
two release numbers (eg, 1.8) and stable releases will use three
numbers (eg, 1.8.1). The prior behavior of using a forth number
(eg, 1.7.5.1) for stable releases will no longer be used.

SeaBIOS 1.7.5
=============

Available on 20140528. Major changes in this release:

* Support for obtaining SMBIOS tables directly from QEMU.
* XHCI USB controller fixes for real hardware (now tested on several
  boards)
* SeaVGABIOS improvements
    * New driver for "coreboot native vga" support
    * Improved detection of older x86emu versions with incorrect
      emulation.
* Several bug fixes and code cleanups

SeaBIOS 1.7.5.1
---------------

Available on 20141113. Stable release containing only bug fixes.

SeaBIOS 1.7.5.2
---------------

Available on 20150112. Stable release containing only bug fixes.

SeaBIOS 1.7.4
=============

Available on 20131223. Major changes in this release:

* Support for obtaining ACPI tables directly from QEMU.
* Initial support for XHCI USB controllers (initially for QEMU only).
* Support for booting from "pvscsi" devices on QEMU.
* Enhanced floppy driver - improved support for real hardware.
* coreboot cbmem console support.
* Optional support for using the 9-segment instead of the e-segment
  for local variables.
* Improved internal timer code and accuracy.
* SeaVGABIOS improvements
    * Better support for legacy X.org releases with incomplete x86emu
      emulation.
    * Support for using an internal stack to reduce caller's stack
      usage.
    * Back port of new "bochs dispi" interface video modes.
* Several bug fixes and code cleanups
    * Source code separated out into additional hardware and firmware
      directories.
    * Update to latest version of Kconfig

SeaBIOS 1.7.3
=============

Available on 20130707. Major changes in this release:

* Initial support for using SeaBIOS as a UEFI Compatibility Support
  Module (CSM)
* Support for detecting and using ACPI reboot ports.
* By default, all 16bit entry points now use an internal stack to
  reduce stack footprint.
* Floppy controller code has been rewritten to improve
  compatibility. Non-standard floppy sizes now work again with recent
  QEMU versions.
* Several bug fixes and code cleanups

SeaBIOS 1.7.2
=============

Available on 20130118. Major changes in this release:

* Support for ICH9 host chipset ("q35") on emulators
* Support for booting from LSI MegaRAID SAS controllers
* Support for using the ACPI PM timer on emulators
* Improved Geode VGA BIOS support.
* Several bug fixes

SeaBIOS 1.7.2.1
---------------

Available on 20130227. Stable release containing only bug fixes.

SeaBIOS 1.7.2.2
---------------

Available on 20130527. Stable release containing only bug fixes.

SeaBIOS 1.7.1
=============

Available on 20120831. Major changes in this release:

* Initial support for booting from USB attached scsi (USB UAS) drives
* USB EHCI 64bit controller support
* USB MSC multi-LUN device support
* Support for booting from LSI SCSI controllers on emulators
* Support for booting from AMD PCscsi controllers on emulators
* New PCI allocation code on emulators. Support 64bit PCI bars and
  mapping them above 4G.
* Support for non-linear APIC ids on emulators.
* Stack switching for 16bit real mode irq handlers to reduce stack
  footprint.
* Support for custom storage in the memory at 0xc0000-0xf0000. No
  longer reserve memory for custom storage in first 640k.
* Improved code generation for 16bit segment register loads
* Boot code will now (by default) reboot after 60 seconds if no boot
  device found
* CBFS and FWCFG "files" are now only scanned one time
* Several bug fixes

SeaBIOS 1.7.0
=============

Available on 20120414. Major changes in this release:

* Many enhancements to VGA BIOS code - it should now be feature
  complete with LGPL vgabios.
* Support for virtio-scsi.
* Improved USB drive (usb-msc) support.
* Several USB controller bug fixes and improvements.
* Runtime ACPI AML PCI hotplug construction.
* Support for running on i386 and i486 CPUs.
* Enhancements to PCI init when running on emulators.
* Several bug fixes

SeaBIOS 1.6.3
=============

Available on 20111004. Major changes in this release:

* Initial support for Xen
* PCI init (on emulators) uses a two-phase initialization
* Fixes for AHCI so it can work on real hardware. AHCI is now enabled
  by default.
* Bootsplash support for BMP files
* Several configuration options can now be configured at runtime via
  CBFS files (eg, "etc/boot-menu-wait")
* PCI device scan is cached during POST phase
* Several bug fixes

The SeaBIOS 1.6.3 release was an incremental feature release. The
first release number (1) was incremented as the project was no longer
in a beta stage, and the third release number (3) was also incremented
to indicate the release was a regular feature release.

SeaBIOS 1.6.3.1
---------------

Available on 20111124. Stable release containing only bug fixes.

SeaBIOS 1.6.3.2
---------------

Available on 20120311. Stable release containing only bug fixes.

SeaBIOS 0.6.2
=============

Available on 20110228. Major changes in this release:

* Setup code can relocate to high-memory to save space in c-f segments
* Build now configured via Kconfig
* Experimental support for AHCI controllers
* Support for run-time configuration of the boot order (via
  CBFS/fw_cfg "bootorder" file)
* Support T13 EDD3.0 spec
* Improved bounds checking on PCI memory allocation
* Several bug fixes

SeaBIOS 0.6.1
=============

Available on 20100913. Major changes in this release:

* Support for virtio drives
* Add ACPI definitions for cpu hotplug support
* Support for a graphical bootsplash screen
* USB mouse support
* The PCI support for emulators is less dependent on i440 chipset
* New malloc implementation which improves memalign and free
* The build system no longer double links objects
* Several bug fixes

SeaBIOS 0.6.1.1
---------------

Available on 20101031. Stable release containing only bug fixes.

SeaBIOS 0.6.1.2
---------------

Available on 20101113. Stable release containing only bug fixes.

SeaBIOS 0.6.1.3
---------------

Available on 20101226. Stable release containing only bug fixes.

SeaBIOS 0.6.0
=============

Available on 20100326. Major changes in this release:

* USB hub support
* USB drive booting support
* USB keyboard auto-repeat support
* USB EHCI controller support
* Several improvements to compatibility of PS2 port handlers for old
  code
* Support for qemu e820 interface
* Several bug fixes and code cleanups

SeaBIOS 0.5.1
=============

Available on 20100108. Major changes in this release:

* Support for 32bit PCI BIOS calls
* Support for int1589 calls
* MPTable fixes for OpenBSD
* ATA DMA and bus-mastering support
* Several bug fixes and code cleanups

SeaBIOS 0.5.0
=============

Available on 20091218. Major changes in this release:

* Several enhancements ported from the Bochs BIOS derived code in qemu
  and kvm
* Support for parallel hardware initialization to reduce bootup times
* Enable PCI option rom support by default (Bochs users must now
  enable CONFIG_OPTIONROMS_DEPLOYED in src/config.h). Support added
  for extracting option roms from qemu "fw_cfg".
* Support USB UHCI and OHCI controllers
* Initial support for USB keyboards
* SeaBIOS can now be greater than 64K
* Support for permanent low memory allocations
* APIC "local interrupts" now enabled in SeaBIOS (on emulators)
* Several bug fixes and code cleanups

SeaBIOS 0.4.2
=============

Available on 20090909. Major changes in this release:

* Implement Post Memory Manager (PMM) support. Use equivalent "malloc"
  functions for internal allocations as well.
* Refactor disk "block" interface for greater expandability
* Support CBFS based floppy images
* Allow boot menu to select either floppy to boot from
* Increase ebda size to store a CDROM harddrive/floppy emulation
  buffer
* Support systems with multiple vga cards (only the card with the
  legacy IO ranges mapped will have its option rom executed)
* Make option rom memory be writable during option rom execution (on
  emulators)
* Compile version number into code and report on each boot
* Several bug fixes and code cleanups

SeaBIOS 0.4.1
=============

Available on 20090714. Major changes in this release:

* Support older versions of gcc that predate "-fwhole-program" (eg,
  v3.x)
* Add initial port of "LGPL vga bios" code into tree in "vgasrc/"
  directory
* Handle ATA drives still "spinning up" during SeaBIOS drive detect
* Add support for option rom Boot Connection Vectors (BCV)
* Enhance boot menu to support booting from any drive or any cdrom
* Support flash based Coreboot File System (CBFS)
* Support booting from a CBFS "payload"
* Support coreboot table forwarder
* Support compile time definitions for multiple root PCI buses
* New tools/readserial.py tool
* Several bug fixes and code cleanups

SeaBIOS 0.4.0
=============

Available on 20090206. Major changes in this release:

* Add Bios Boot Specification (BBS) calls; add PnP call stubs
* Support option roms stored in PCI rom BAR
* Support rebooting on ctrl+alt+delete key press
* Scan PCI devices for ATA adapters (don't assume legacy ISA ATA ports
  are valid)
* Attempt to automatically determine gcc capabilities/bugs during
  build
* Add script to layout 16bit sections at fixed offsets and in
  compacted space
* Introduce timestamp counter based delays
* Support POST calls that are really a resume
* Use new stack in EBDA for int13 disk calls to reduce stack usage
* Support the EBDA being relocated by option roms
* Move many variables from EBDA to global variables (stored in
  f-segment)
* Support for PCI bridges when iterating through PCI device list
* Initial port of several KVM specific features from their Bochs BIOS
  derived code
* Access BDA using segment 0x40 and IVT using segment 0x00 (which
  could be important for 16bit protected mode callers)
* Several bug fixes and code cleanups

SeaBIOS 0.3.0
=============

Available on 20080817. Major changes in this release:

* Run boot code (int18/19) in 32bit mode
* Rewrite of PS2 port handling - new code is more compatible with real
  hardware
* Initial support for int155f VGA option rom calls
* Several bug fixes and code cleanups

SeaBIOS 0.2.3
=============

Available on 20080702. Major changes in this release:

* Initial support for running on real hardware with coreboot
* Support parsing coreboot tables
* Support relocating bios tables from high memory when running under
  coreboot
* Dynamic e820 map generation
* Serial debug support
* New tools/checkstack.py tool
* Several bug fixes and code cleanups

SeaBIOS 0.2.2
=============

Formerly known as "legacybios". Available on 20080501. Major changes
in this release:

* Several bug fixes and code cleanups

SeaBIOS 0.2.1
=============

Formerly known as "legacybios". Available on 20080406. Major changes
in this release:

* Port of boot menu code from Bochs BIOS
* Several bug fixes and code cleanups

SeaBIOS 0.2.0
=============

Formerly known as "legacybios". Available on 20080330. Major changes
in this release:

* Completion of initial port of Bochs BIOS code to gcc.
