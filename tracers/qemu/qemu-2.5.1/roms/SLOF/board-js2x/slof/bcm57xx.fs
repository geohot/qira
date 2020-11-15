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

\ Handle bcm57xx device

s" network" device-type

my-space pci-alias-net

VARIABLE obp-tftp-package

0 VALUE bcm57xx-priv
0 VALUE open-count

: open  ( -- okay? )
   open-count 0= IF
      open IF
         bcm57xx-open dup not IF ." bcm57xx-open failed" EXIT THEN
         drop dup TO bcm57xx-priv
         6 encode-bytes s" local-mac-address" property
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
    open-count 0> IF
      open-count 1 - dup to open-count
      0= IF
         bcm57xx-priv bcm57xx-close
         close
      THEN
   THEN
   s" close" obp-tftp-package @ $call-method
;

: read ( buf len -- actual )
   dup IF
      bcm57xx-read
   ELSE  
      nip
   THEN
;

: write ( buf len -- actual )
   dup IF
      bcm57xx-write
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
