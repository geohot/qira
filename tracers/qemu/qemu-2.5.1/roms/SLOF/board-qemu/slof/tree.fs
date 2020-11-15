\ *****************************************************************************
\ * Copyright (c) 2004, 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

: strequal ( str1 len1 str2 len2 -- flag )
  rot dup rot = IF comp 0= ELSE 2drop drop 0 THEN ; 

400 cp

\ The root of the device tree and some of its kids.
" /" find-device

\ The following properties have been provided by the FDT from QEMU already,
\ so we do not have to create them on our own:

\ " QEMU" encode-string s" model" property
\ 2 encode-int s" #address-cells" property
\ 2 encode-int s" #size-cells" property
\ s" chrp" device-type

480 cp

\ See 3.6.5, and the PowerPC OF binding document.
new-device
s" mmu" 2dup device-name device-type
0 0 s" translations" property

: open  true ;
: close ;

finish-device
device-end

4c0 cp

\ Fixup timebase frequency from device-tree
: fixup-tbfreq
    " /cpus/@0" find-device
    " timebase-frequency" get-node get-package-property IF
        2drop
    ELSE
        decode-int to tb-frequency 2drop
    THEN
    device-end
;
fixup-tbfreq

4d0 cp

include fbuffer.fs

500 cp

: populate-vios ( -- )
    \ Populate the /vdevice children with their methods
    \ WARNING: Quite a few SLOFisms here like get-node, set-node, ...

    ." Populating /vdevice methods" cr
    " /vdevice" find-device get-node child
    BEGIN
        dup 0 <>
    WHILE
        dup set-node
        dup " compatible" rot get-package-property 0 = IF
            drop dup from-cstring
            2dup " hvterm1" strequal IF
                " vio-hvterm.fs" included
            THEN
            2dup " IBM,v-scsi" strequal IF
                " vio-vscsi.fs" included
            THEN
            2dup " IBM,l-lan" strequal IF
                " vio-veth.fs" included
            THEN
	    2dup " qemu,spapr-nvram" strequal IF
	    	" rtas-nvram.fs" included
	    THEN
            2drop
       THEN
       peer
    REPEAT drop

    device-end
;

\ Now do it
populate-vios

580 cp

5a0 cp

#include "pci-scan.fs"

: populate-pci-busses ( -- )
    \ Populate the /pci* children with their methods
    " /" find-device get-node child
    BEGIN
        dup 0 <>
    WHILE
        dup set-node
        dup " name" rot get-package-property 0 = IF
            drop dup from-cstring
            2dup s" pci" strequal IF
                s" pci-phb.fs" included
            THEN
            2drop
       THEN
       peer
    REPEAT drop

    device-end
;

populate-pci-busses

600 cp

: check-patch-kernel-sc1 ( -- )
    \ At this point we can try our best to patch the kernel. This function
    \ gets called from the "quiesce" call that kernels execute before they
    \ take over the system.
    \
    \ Here we know that ciregs->r4 contains the return address that gets us
    \ back into enter_prom inside the guest kernel.
    \ We assume that within a range of +- 16MB of that pointer all sc 1
    \ instructions inside of that kernel reside.

    \ test_ins (instruction that tells us the kernel's endianness; we use the
    \           return address back into the kernel here.)
    ciregs >r4 @
    \ test_ins + 16MB (end of search range)
    dup 1000000 +
    \ MAX(test_ins - 16MB, 0) (start of search range)
    dup 2000000 < IF 0 ELSE dup 2000000 - THEN
    swap
    check-and-patch-sc1
;

\ Add sc 1 patching
' check-patch-kernel-sc1 add-quiesce-xt

\ Add rtas cleanup last
' rtas-quiesce add-quiesce-xt

640 cp

690 cp

6a0 cp

6a8 cp

6b0 cp

6b8 cp

6c0 cp

s" /cpus/@0" open-dev encode-int s" cpu" set-chosen
s" /memory@0" open-dev encode-int s" memory" set-chosen

6e0 cp

700 cp

\ See 3.5.
s" /openprom" find-device
   s" SLOF," slof-build-id here swap rmove here slof-build-id nip $cat encode-string s" model" property
   0 0 s" relative-addressing" property
device-end

s" /aliases" find-device
   : open  true ;
   : close ;
device-end

s" /mmu" open-dev encode-int s" mmu" set-chosen

#include "available.fs"

\ Setup terminal IO

#include <term-io.fs>

