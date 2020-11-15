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

\ U4 "Attu" PCIe root complex.

\ See the PCI OF binding document.

new-device

s" pciex" device-name s" pci" device-type
s" U4-pcie" compatible
s" U4" encode-string s" model" property

\ spare out 0xc0000000-0xefffffff for pcie
f8070200 rl@ fffffff0 and f8070200 rl!
\ enable io memory for pcie @ c0000000-efffffff
70000003 f80903f0 rl!-le

3 encode-int s" #address-cells" property
2 encode-int s" #size-cells" property

s" /mpic" find-node encode-int s" interrupt-parent" property
\ XXX should have interrupt map, etc.  this works for now though.

: decode-unit  2 hex-decode-unit  3 #join  8 lshift  0 0 rot F00000 + ;
: encode-unit  nip nip  ff00 and 8 rshift  3 #split
               over IF 2 ELSE nip 1 THEN hex-encode-unit ;

f1000000 CONSTANT my-puid
\ Configuration space accesses.
: >config  f1000000 + ;
: config-l!  >config rl!-le ;
: config-l@  >config rl@-le ;
: config-w!  >config rw!-le ;
: config-w@  >config rw@-le ;
: config-b!  >config rb! ;
: config-b@  >config rb@ ;

: config-dump ( addr size -- )  ['] config-l@ 4 (dump) ;

\ 16MB of configuration space
f1000000 encode-64 1000000 encode-64+ s" reg" property

\ 4MB of I/O space.
01000000 encode-int  00000000 encode-int+ 00000000 encode-int+ 
00000000 encode-int+ f0000000 encode-int+ 
00000000 encode-int+ 00400000 encode-int+

\ 1.75GB of memory space @ c0000000.
02000000 encode-int+ c0000000 encode-64+
c0000000 encode-64+  30000000 encode-64+ s" ranges" property

\ Host bridge, so full bus range.
f0 encode-int ff encode-int+ s" bus-range" property

: open  true ;
: close ;

\ : probe-pci-host-bridge ( bus-max bus-min mmio-max mmio-base mem-max mem-base io-max io-base my-puid -- )
s" /mpic" find-node my-puid pci-irq-init drop

00fff1f0 18 config-l!

ff F0 f0000000 e8000000 e8000000 c0000000 100000000 f000
my-puid probe-pci-host-bridge

\ \ PCIe debug / fixup
: find-pcie-cap  ( devfn -- offset | 0 )
   >r 34  BEGIN  r@ + config-b@ dup ff <> over and  WHILE
       dup r@ + config-b@ 10 =  IF
          r> drop EXIT
       THEN 1+
   REPEAT r> 2drop 0
;

 : (set-ps) ( ps addr -- )
   8 + >r 5 lshift r@ config-w@ ff1f and or r> config-w! ;
 : set-ps ( ps -- )
   log2 7 -
   10000 0 DO i 8 lshift dup find-pcie-cap ?dup IF
   + 2dup (set-ps) THEN drop LOOP drop ;
 
 : (set-rr) ( rr addr -- )
   8 + >r c lshift r@ config-w@ 8fff and or r> config-w! ;
 : set-rr ( rr -- )
   log2 7 -
   10000 0 DO i 8 lshift dup find-pcie-cap ?dup IF
   + 2dup (set-rr) THEN drop LOOP drop ;

80 set-ps  80 set-rr  

finish-device
