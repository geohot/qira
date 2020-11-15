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

\ Create debug section in NVRAM
: debug-init-nvram ( -- )
   nvram-partition-type-debug get-nvram-partition IF
      cr ." Could not find debug partition in NVRAM - "
      nvram-partition-type-debug s" debug" d# 1024 new-nvram-partition
      ABORT" Failed to create DEBUG NVRAM partition"
      2dup erase-nvram-partition drop
      ." created." cr
   THEN
   s" debug-nvram-partition" $2constant
;

debug-init-nvram

: debug-add-env ( "name" "value" -- ) debug-nvram-partition 2rot 2rot internal-add-env drop ;
: debug-set-env ( "name" "value" -- ) debug-nvram-partition 2rot 2rot internal-set-env drop ;
: debug-get-env ( "name" -- "value" TRUE | FALSE) debug-nvram-partition 2swap internal-get-env ;

: debug-get-history-enabled ( -- n )	s" history-enabled?" debug-get-env IF $number IF 0 THEN ELSE 0 THEN ;
: debug-set-history-enabled ( n -- )	(.) s" history-enabled?" 2swap debug-set-env ;


debug-get-history-enabled constant nvram-history?

nvram-history? [IF]

: history-init-nvram ( -- )
   nvram-partition-type-history get-nvram-partition IF
      cr ." Could not find history partition in NVRAM - "
      nvram-partition-type-history s" history" d# 2048 new-nvram-partition
      ABORT" Failed to create SMS NVRAM partition"
      2dup erase-nvram-partition drop
      ." created" cr
   THEN
   s" history-nvram-partition" $2constant
;

history-init-nvram

0 value (history-len)
0 value (history-adr)

: (history-load-one) ( str len -- len )
   \ 2dup ." loading " type cr
   to (history-len) to (history-adr)
   /his (history-len) + alloc-mem ( his )
   his-tail 0= IF dup to his-tail THEN
   his-head over his>next ! to his-head
   his-head his>next @  his>prev his-head swap !
   (history-len) his-head his>len !
   (history-adr) his-head his>buf (history-len) move
   (history-len) 1+
;

: history-load ( -- )
   history-nvram-partition drop BEGIN dup WHILE
      dup rzcount ( part str len )
      dup IF
         (history-load-one) +
      ELSE
         3drop 0
      THEN
   REPEAT
   drop
;

: (history-store-one) ( pos len saddr slen -- FALSE | npos nlen TRUE )
   dup 3 pick < IF \ enough space
      dup >r rot >r
      \ 2dup ." storing " type cr
      bounds DO dup i c@ swap nvram-c! 1+ LOOP
      dup 0 swap nvram-c! 1+
      r> r> - 1- true
   ELSE
      2drop false
   THEN
;

: history-store ( -- )
   history-nvram-partition erase-nvram-partition drop
   history-nvram-partition his-tail BEGIN dup WHILE
      dup his>buf over his>len @
      ( position len link saddr slen )
      rot >r (history-store-one) r> 
      swap IF his>prev @ ELSE drop 0 THEN
   REPEAT
   2drop drop
;

\ redefine "end of SLOF" words to safe history
: reset-all history-store reset-all ;
: reboot history-store reboot ;
: boot history-store boot ;

[THEN]
