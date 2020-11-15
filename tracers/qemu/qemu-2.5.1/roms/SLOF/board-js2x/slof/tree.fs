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

400 cp

0 value puid

: >conf-rtas ( config-addr  -- config-addr )
   puid f2000000 >= IF
      ffffff AND                        \ Mask away highest byte for normal PCI
      dup ffff > IF
         1000000 +
      THEN
   THEN
   puid +
;

: rtas-config-b@ ( config-addr -- value ) >conf-rtas rb@ ;
: rtas-config-b! ( value config-addr -- ) >conf-rtas rb! ;
: rtas-config-w@ ( config-addr -- value ) >conf-rtas rw@-le ;
: rtas-config-w! ( value config-addr -- ) >conf-rtas rw!-le ;
: rtas-config-l@ ( config-addr -- value ) >conf-rtas rl@-le ;
: rtas-config-l! ( value config-addr -- ) >conf-rtas rl!-le ;

440 cp

#include "pci-scan.fs"

480 cp

\ The root of the device tree and some of its kids.

s" /" find-device
\ read model string from VPD
vpd-read-model ( straddr strlen )
\ if it is a bimini, we replace the "IBM," in the model string with "TSS,"
bimini? IF
   2dup drop 4 ( straddr strlen str 4 ) \ for string comparison: only first 4 bytes ("IBM,")
   \ string comparison
   s" IBM," str= IF
      \ model starts with "IBM,", we replace it with "TSS,"
      2dup drop s" TSS," ( straddr strlen straddr replacestr len )
      rot swap ( straddr strlen replacestr straddr len ) \ correct order for move: src dest len
      move ( straddr strlen ) \ now we have TSS, at beginning of str...
   THEN
THEN
\ store the model string
encode-string s" model" property

2 encode-int s" #address-cells" property
2 encode-int s" #size-cells" property

\ XXX: what requires this?  Linux?
0 encode-int  f8040000 encode-int+
0 encode-int+ f8050000 encode-int+ s" platform-open-pic" property

\ Yaboot is stupid.  Without this, it can't/won't find /etc/yaboot.conf.
s" chrp SLOF based 970 blade" device-type

\ add more information to the compatible property
js21?  IF
   bimini?  IF
      s" IBM,Bimini"
   ELSE
      s" IBM,JS21"
   THEN
ELSE
   s" IBM,JS20"
THEN  encode-string
\ To get linux-2.6.10 and later to work out-of-the-box.
s" Momentum,Maple" encode-string encode+ s" compatible" property


\ See 3.6.5, and the PowerPC OF binding document.
new-device
s" mmu" 2dup device-name device-type
0 0 s" translations" property

: open  true ;
: close ;

finish-device

new-device flash-addr set-unit-64
   s" flash" 2dup device-name device-type
   0 encode-int flash-addr encode-int+
   0 encode-int+ get-flash-size encode-int+ s" reg" property
   get-flash-size encode-int s" #bytes" property
   0 0 s" used-by-rtas" property
   : open  true  ;
   : close  ;
finish-device

4a0 cp

new-device nvram-base set-unit-64
   s" nvram" 2dup device-name device-type
   nvram-size encode-int s" #bytes" property
   0 encode-int nvram-base encode-int+
   0 encode-int+ nvram-size encode-int+ s" reg" property
   get-node node>path s" nvram" 2swap set-alias
   : open  true  ;
   : close  ;
finish-device

4c0 cp

#include "memory.fs"

500 cp

#include "mpic.fs"

580 cp

#include "dart.fs"

5a0 cp

#include "i2c.fs"

600 cp
get-node device-end
620 cp
\ if it is js21/bimini the fbuffer code is included
u4? ?include fbuffer.fs
640 cp
set-node

690 cp

#include "ht.fs"

6b0 cp

u4? ?include attu.fs
6c0 cp

\ See the PowerPC OF binding document.
new-device
s" cpus" device-name

1 encode-int s" #address-cells" property
0 encode-int s" #size-cells" property

: decode-unit  1 hex-decode-unit ;
: encode-unit  1 hex-encode-unit ;

cpu-mask @ 40 0 DO dup 1 and IF
i s" cpu.fs" INCLUDED THEN u2/ LOOP drop

: open  true ;
: close ;

finish-device

master-cpu s" /cpus/@" rot (u.) $cat open-dev encode-int s" cpu" set-chosen
s" /memory" open-dev encode-int s" memory" set-chosen

6e0 cp

new-device
   s" rtas" device-name

   rtas-size encode-int s" rtas-size" property
   00000001 encode-int s" ibm,flash-block-version" property
   00000001 encode-int s" rtas-event-scan-rate" property
   rtas-create-token-properties
   00000001 encode-int s" rtas-version" property

: open  true ;
: close ;

: instantiate-rtas instantiate-rtas ;

finish-device

700 cp

device-end

\ Hack for AIX.
s" /options" find-device
   \ s" 33554432" encode-string s" load-base" property
   s" 16384" encode-string s" load-base" property
device-end

\ See 3.5.
s" /openprom" find-device
   s" SLOF," slof-build-id here swap rmove here slof-build-id nip $cat encode-string s" model" property
   0 0 s" relative-addressing" property
   flashside? 1 = IF s" T" ELSE s" P" THEN
   encode-string s" ibm,fw-bank" property
   takeover? not  IF
      0 set-flashside drop
      read-version-and-date  s" ibm,fw-perm-bank" property
      1 set-flashside drop
      read-version-and-date  s" ibm,fw-temp-bank" property
      flashside? set-flashside drop
   THEN
device-end

s" /aliases" find-device
   : open  true ;
   : close ;
device-end

s" /mmu" open-dev encode-int s" mmu" set-chosen

#include "available.fs"

#include <term-io.fs>

u3? IF s" /ht/isa/serial@3f8" io
  ELSE s" /ht/isa/serial@2f8" io THEN

