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

." Populating " pwd cr

s" network" device-type

0 VALUE virtfs-rx-buffer
0 VALUE virtfs-tx-buffer
FALSE VALUE initialized?

2000 CONSTANT VIRTFS-BUF-SIZE \ 8k

/vd-len BUFFER: virtiodev
virtiodev virtio-setup-vd

\
\ Support methods.

: shutdown  ( -- )
   initialized? 0= IF EXIT THEN
   virtiodev virtio-fs-shutdown
   virtfs-rx-buffer VIRTFS-BUF-SIZE free-mem
   virtfs-tx-buffer VIRTFS-BUF-SIZE free-mem
   FALSE to initialized?
;

: init  ( -- success )
   VIRTFS-BUF-SIZE alloc-mem to virtfs-rx-buffer
   VIRTFS-BUF-SIZE alloc-mem to virtfs-tx-buffer
   
   virtiodev			( dev )
   virtfs-tx-buffer		( dev tx )
   virtfs-rx-buffer		( reg tx rx )
   VIRTFS-BUF-SIZE		( reg tx rx size )   
   virtio-fs-init		( success )
   
   dup IF
      TRUE to initialized?
      ['] shutdown add-quiesce-xt
   THEN
;

\
\ Standard network interface.

: open  ( -- okay? )
   open 0= IF false EXIT THEN
   initialized? 0= IF
      init 0= IF false EXIT THEN
   THEN   
   true
;

: load ( addr -- len )
   virtiodev swap		( dev addr )   
   my-args   			( dev addr str strlen )
   1 +		\ hack to make the following allocate 1 more byte
   \-to-/	\ convert path elements
   1 - 2dup + 0 swap c! drop
   virtio-fs-load		( length )
;

: close  ( -- )
   initialized? IF
      shutdown
   THEN
   close
;

: ping ( -- )
   cr s" ping not supported for this device" type cr cr
;


: (set-alias)
    " virtfs" find-alias 0= IF
        " virtfs" get-node node>path set-alias
    ELSE
        drop
    THEN
;

\
\ Init the module.

(set-alias)
