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

s" block" device-type

FALSE VALUE initialized?

\ Required interface for deblocker

200 VALUE block-size
8000 CONSTANT max-transfer 

INSTANCE VARIABLE deblocker

/vd-len BUFFER: virtiodev
virtiodev virtio-setup-vd

\ Quiesce the virtqueue of this device so that no more background
\ transactions can be pending.
: shutdown  ( -- )
    initialized? IF
        my-phandle node>path open-dev ?dup IF
            virtiodev virtio-blk-shutdown
            close-dev
        THEN
        FALSE to initialized?
    THEN
;

\ Basic device initialization - which has only to be done once
: init  ( -- )
   virtiodev virtio-blk-init to block-size
   TRUE to initialized?
   ['] shutdown add-quiesce-xt
;

\ Read multiple blocks - called by deblocker package
: read-blocks  ( addr block# #blocks -- #read )
   virtiodev virtio-blk-read
;

\ Standard node "open" function
: open  ( -- okay? )
   open 0= IF false EXIT THEN
   dup initialized? 0= AND IF
      init
   THEN
   0 0 s" deblocker" $open-package dup deblocker ! dup IF
      s" disk-label" find-package IF
         my-args rot interpose
      THEN
   THEN
   0<>
;

\ Standard node "close" function
: close  ( -- )
   deblocker @ close-package
   close
;

\ Standard node "seek" function
: seek  ( pos.lo pos.hi -- status )
   s" seek" deblocker @ $call-method
;

\ Standard node "read" function
: read  ( addr len -- actual )
   s" read" deblocker @ $call-method
;

\ Set disk alias if none is set yet
: (set-alias)
   s" disk" get-next-alias ?dup IF
      get-node node>path set-alias
   THEN
;
(set-alias)
