\ *****************************************************************************
\ * Copyright (c) 2013 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Handle e1000 device

s" network" device-type

INSTANCE VARIABLE obp-tftp-package
get-node CONSTANT my-phandle
10 config-l@ translate-my-address 3 not AND CONSTANT baseaddr

0 VALUE e1k-priv
0 VALUE open-count

: open  ( -- okay? )
   open-count 0= IF
       open IF
	 baseaddr
         e1k-open dup not IF ." e1k-open failed" EXIT THEN
         drop TO e1k-priv
         true
      ELSE
         false
      THEN
   ELSE
      true
   THEN
   my-args s" obp-tftp" $open-package obp-tftp-package !
   open-count 1 + to open-count
;


: close  ( -- )
   my-phandle set-node
   open-count 0> IF
      open-count 1 - dup to open-count
      0= IF
         e1k-priv e1k-close
         close
      THEN
   THEN
   s" close" obp-tftp-package @ $call-method
;

: read ( buf len -- actual )
   dup IF
      e1k-read
   ELSE  
      nip
   THEN
;

: write ( buf len -- actual )
   dup IF
      e1k-write
   ELSE
      nip
   THEN
;

: load  ( addr -- len )
   s" load" obp-tftp-package @ $call-method
;

: ping  ( -- )
   s" ping" obp-tftp-package @ $call-method
;

6 BUFFER: local-mac
: setup-mac ( -- )
   pci-mem-enable
   " vendor-id" get-node get-property IF EXIT THEN
   decode-int nip nip
   " device-id" get-node get-property IF EXIT THEN
   decode-int nip nip
   baseaddr
   local-mac e1k-mac-setup IF
      encode-bytes  " local-mac-address"  property
   THEN
;

setup-mac

: setup-alias  ( -- )
   " net" get-next-alias ?dup IF
      get-node node>path set-alias
   THEN
;
setup-alias
