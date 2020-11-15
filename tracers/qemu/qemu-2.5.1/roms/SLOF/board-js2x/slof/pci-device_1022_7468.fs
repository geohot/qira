\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

my-space assign-all-device-bars
my-space pci-device-props
my-space pci-set-irq-line

\ See the "ISA/EISA/ISA-PnP" OF binding document.

.( isa)

s" isa" 2dup device-name device-type
\ We have to say it's ISA i.s.o. LPC, as otherwise Linux can't find
\ the serial port for its console.  Linux uses the name instead of the
\ device type (and it completely ignores any "compatible" property).

2 encode-int s" #address-cells" property
1 encode-int s" #size-cells" property

\ We assume all ISA addresses to refer to I/O space.
: decode-unit  1 hex-decode-unit 1 ;
: encode-unit  drop 1 hex-encode-unit ;

\ 32kB of ISA I/O space.
1 encode-int my-space 01000000 + encode-64+ 0 encode-int+ 0 encode-int+
8000 encode-int+ s" ranges" property

: open  true ;
: close ;

\ There's a SIO chip on the LPC bus.
INCLUDE sio.fs

\ There's also an Atmel TPM chip on JS21
\ removed on Bimini Pass 2 and therefore disabled on all Biminis
u4? bimini? not and ?INCLUDE tpm.fs

\ And finally there's the IPMI interface to the BMC.
u4? ?INCLUDE ipmi-kcs.fs

cr
