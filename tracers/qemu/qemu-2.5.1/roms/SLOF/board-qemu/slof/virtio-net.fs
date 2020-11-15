\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ ." Populating " pwd cr

s" network" device-type

INSTANCE VARIABLE obp-tftp-package

/vd-len BUFFER: virtiodev
virtiodev virtio-setup-vd
0 VALUE virtio-net-priv
0 VALUE open-count

: open  ( -- okay? )
   open-count 0= IF
      open IF
         \ my-unit 1 rtas-set-tce-bypass
         s" local-mac-address" get-node get-property not IF
            virtiodev virtio-net-open dup not IF ." virtio-net-open failed" EXIT THEN
            drop TO virtio-net-priv
         THEN
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
         virtio-net-priv virtio-net-close
         \ my-unit 0 rtas-set-tce-bypass
         close
      THEN
   THEN
   s" close" obp-tftp-package @ $call-method
;

: read ( buf len -- actual )
   dup IF
      virtio-net-read
   ELSE
      nip
   THEN
;

: write ( buf len -- actual )
   dup IF
      virtio-net-write
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

\ Set up MAC address from config virtqueue
6 BUFFER: local-mac
: setup-mac  ( -- )
   6 0 DO
      virtiodev i 1 virtio-get-config
      local-mac i + c!
   LOOP
   local-mac 6 encode-bytes  s" local-mac-address"  property
;
setup-mac

: setup-alias  ( -- )
   " net" get-next-alias ?dup IF
      get-node node>path set-alias
   THEN
;
setup-alias
