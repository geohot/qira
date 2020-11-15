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

s" obp-tftp" device-name

INSTANCE VARIABLE ciregs-buffer

: open ( -- okay? ) 
    ciregs-size alloc-mem ciregs-buffer ! 
    true
;

: load ( addr -- size )

    \ Save old client interface register 
    ciregs ciregs-buffer @ ciregs-size move

    s" bootargs" get-chosen 0= IF 0 0 THEN >r >r
    s" bootpath" get-chosen 0= IF 0 0 THEN >r >r

    \ Set bootpath to current device
    my-parent ihandle>phandle node>path encode-string
    s" bootpath" set-chosen

    \ Generate arg string for snk like
    \ "netboot load-addr length filename"
    (u.) s" netboot " 2swap $cat s"  60000000 " $cat

    \ Allocate 1720 bytes to store the BOOTP-REPLY packet
    6B8 alloc-mem dup >r (u.) $cat s"  " $cat
    huge-tftp-load @ IF s"  1 " ELSE s"  0 " THEN $cat
    \ Add desired TFTP-Blocksize as additional argument
    s" 1432 " $cat
    \ Add OBP-TFTP Bootstring argument, e.g. "10.128.0.1,bootrom.bin,10.128.40.1"
    my-args $cat

    \ Call SNK netboot loadr
    (client-exec) dup 0< IF drop 0 THEN

    \ Restore to old client interface register 
    ciregs-buffer @ ciregs ciregs-size move

    \ Recover buffer address of BOOTP-REPLY packet
    r>

    r> r> over IF s" bootpath" set-chosen ELSE 2drop THEN
    r> r> over IF s" bootargs" set-chosen ELSE 2drop THEN

    \ Store BOOTP-REPLY packet as property
    dup 6B8 encode-bytes s" bootp-response" s" /chosen" find-node set-property

    \ free buffer
    6B8 free-mem
;

: close ( -- )
   ciregs-buffer @ ciregs-size free-mem 
;

: ping  ( -- )
   s" ping " my-args $cat (client-exec)
;
