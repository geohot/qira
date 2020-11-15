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


\ Citrine storage controller.
2dup type

device-name s" ide" device-type


3 encode-int s" #address-cells" property
0 encode-int s" #size-cells" property

: decode-unit  3 hex-decode-unit ;
: encode-unit  3 hex-encode-unit ;


: >ioa  [ 10 config-l@ -10 and ] LITERAL + ;
: ioa@  >ioa rl@-le ;
: ioa!  >ioa rl!-le ;


\ Clear request completion doorbell.
2 228 ioa!

\ status
CREATE ioasa 200 allot  ioasa 200 erase \ can reduce to 8 later

\ request/response queue
CREATE rrq 100 allot  rrq 100 erase \ can be smaller

\ data descriptor
CREATE ioadl 8 allot

\ control block
CREATE ioarcb 80 allot  ioarcb 80 erase
ioarcb dup l!
60708090 ioarcb c + l! \ user handle
ioadl ioarcb 2c + l! \ read ioadl
ioasa ioarcb 34 + l!  200 ioarcb 38 + w!

\ ioa config data (max. 16 devices)
CREATE ioacfg 404 allot  ioacfg 404 erase
CREATE setsupbuff  2c allot
   setsupbuff 2c erase
   2c setsupbuff w!
   1 setsupbuff 3 + c!

: wait-ready ( -- )
	82800000 214 ioa!
	80000000 BEGIN dup 224 ioa@ cr .s dup 8000000 and IF 
		cr ." Unit check on SAS-Controller detected"
		cr 42c ioa@ .
		8 110 ioa!
 		BEGIN cr 0 config-l@ dup . ffffffff <> UNTIL
\		ABORT" Unit check on SAS-Controller detected"
	THEN
	and
	UNTIL drop 
;

\ wait-ready

: wait-ioa ( int-mask -- )  BEGIN dup 224 ioa@ and UNTIL drop ;
: init-ioa ( -- )  82800000 214 ioa!  80000000 wait-ioa ;
: do-request ( -- )  ioasa 20 erase  ioarcb 404 ioa!
                     2 wait-ioa 2 228 ioa! 
;

: setup-ioarcb ( rsrc type addr len -- )
  tuck  49000000 or ioadl l!  ioadl 4 + l! \ setup ioadl
  ioarcb 20 + l!  ioadl ioarcb 2c + l! 8 ioarcb 30 + l! \ set len, ioadl addr
  ioarcb 3e + c!  ioarcb 8 + l! \ set type and resource
  ioarcb 40 + 40 erase ;

: setup-wrioarcb ( rsrc type addr len -- )
  tuck  49000000 or ioadl l!  ioadl 4 + l! \ setup ioadl
  ioarcb 1C + l!  ioadl ioarcb 24 + l! 8 ioarcb 28 + l! \ set len, ioadl addr
  ioarcb 3e + c!  ioarcb 8 + l! \ set type and resource
  ioarcb 40 + 40 erase ;

: setup-idrrq ( rrq len -- )
  c4 ioarcb 42 + c!  8 lshift ioarcb 48 + l!  ioarcb 44 + l! ;
: do-idrrq ( -- )  -1 1 0 0 setup-ioarcb  rrq 100 setup-idrrq  do-request ;

: setup-query ( len -- )  c5 ioarcb 42 + c!  8 lshift ioarcb 48 + l! ;
: do-query ( -- )  -1 1 ioacfg 404 setup-ioarcb  404 setup-query  do-request ;

: setup-startUnit ( -- )  1b ioarcb 42 + c! 3 ioarcb 46 + c! ;
: do-startUnit ( hndl -- )  0 0 0 setup-ioarcb  setup-startUnit  do-request ;

: setup-setsupported ( len -- ) 80 ioarcb 40 + c! fb ioarcb 42 + c! 8 lshift ioarcb 48 + l! ;
: do-setsupported (  -- )  -1 1 setsupbuff 2c setup-wrioarcb  2c setup-setsupported  do-request ;

\ ********************************
\ read capacity
\ ********************************
CREATE cap 8 allot

: setup-cap ( -- ) 25 ioarcb 42 + c!  cap 8 erase ;
: do-cap ( rsrc addr -- )
  >r 0 r> 8 setup-ioarcb  setup-cap  do-request ;

: .id  ( id -- )  ." @" lwsplit 2 0.r ." ," wbsplit 2 0.r ." ," 2 0.r ;

: .cap ( rsrc -- )
  cap do-cap cap l@ cap 4 + l@ * d# 50000000 + d# 100000000 /
  base @ >r decimal d# 10 /mod 4 .r ." ." 0 .r ." GB" r> base ! ;

\ ********************************
\ Test Unit Ready
\ ********************************
: setup-test-unit-ready ( -- )
   00 ioarcb 42 + c!   \ SCSI cmd: Test-Unit-Ready
;

: do-test-unit-ready       ( rsrc -- )
   0 0 0 setup-ioarcb      ( rsrc type addr len -- )
   setup-test-unit-ready
   do-request
;

\ ********************************
\ Check devices
\ ********************************
: check-device  ( ioacfg-entry -- )
   dup 2 + w@ 2001 and 0<>       \ generic or raid disk
   IF                            \ is an IOA resource ?
      dup 8 + l@                 ( ioacfg-entry rsrc )  \ get resource handle
      8 0
      DO                         ( ioacfg-entry rsrc )
         dup do-test-unit-ready  ( ioacfg-entry rsrc )
         ioasa l@ 0=             \ read returned status
         IF
            LEAVE
         THEN
      LOOP
      drop                       ( ioacfg-entry )
   THEN
   drop  (  )
;

: check-devices   ( -- )
   ioacfg 4 +     ( ioacfg-entry )  \ config block for 16 devices
   ioacfg c@ 0    \ amount of detected devices
   ?DO
      dup
      check-device   ( ioacfg-entry )
      40 +
   LOOP
   drop
;

\ ********************************
\ Show Devices
\ ********************************
: show-device  ( ioacfg-entry -- )
   cr ."     " dup 2 + w@
   dup 8000 and  IF  ." Controller         :"  THEN
   dup 2000 and  IF  ."  Disk (RAID Member):"  THEN
   dup 0002 and  IF  ."  Disk (Volume Set) :"  THEN
   0001 and  IF  ."  Disk (Generic)    :"  THEN
   space dup 4 + l@ ffffff and dup ffffff <>  IF
      .id
   ELSE  drop 9 spaces  THEN  space
   dup 1c + 8 type space dup 24 + 10 type
   dup 2 + w@ 8000 and 0=  IF
      space dup 8 + l@ .cap 
   THEN drop
;

: show-devices  ( -- )
   ioacfg 4 + ioacfg c@ 0
   ?DO dup show-device 40 + LOOP drop
;

: setup-read  ( lba len -- ) \ len is in blocks
   28 ioarcb 42 + c!
   swap ioarcb 44 + l!
   8 lshift ioarcb 48 + l!
;

: do-read  ( hndl lba len addr -- )  \ len is in blocks
   over >r rot >r swap 0 -rot 200 * ( 0 hndl addr len* ) 
   setup-ioarcb r> r> ( lba len ) 
   setup-read do-request 
;

: make-subnode  ( rsrc-type rsrc-handle id -- )
   rot 2 and  IF  \ only device which are part of a RAID should be started
      over do-startUnit  \ at least on citrine there are problems starting
                         \ Generic SCSI devices
   THEN  do-setsupported
   dup ffffff <>  IF
      \ we need max-#blocks for citrine-disk.fs
                             ( rsrc id )
      over cap do-cap cap l@ ( rsrc id max-#blocks )
      swap rot swap ( max-#block rsrc id ) \ this is what citrine-disk.fs expects...
      s" citrine-disk.fs" included
   ELSE
      2drop
   THEN
;

: make-subnodes  ( -- )
   ioacfg 4 + ioacfg c@ 0  ?DO  dup 2 + w@ dup  ( ioacfg rsrc-type rsrc-type )
   A000  \ 8000 = Resource Subtype is IOA Focal Point.
         \ 2000 = Device is a member of a data redundancy group (eg. RAID).
         \ (1000 = Device is designated for use as a hot spare.
         \         Unfortunately obsidian reports disk which are not part of
         \         of a RAID also as hot space even if they are not.)
         \ all these devices should not appeat in DT
         \ SIS40 page 60
   and 0=  IF
      swap dup  ( rsrc-type ioacfg ioacfg )
      8 + l@ over 4 + l@  ( rsrc-type ioacfg rsrc-handle rsrc-addr )
      ffffff and 2swap swap 2swap  ( ioacfg rsrc-type rsrc-handle rsrc-addr )
      make-subnode  ELSE  drop  THEN  40 +  LOOP  drop ;

: do-it  ( -- )
   init-ioa do-idrrq
   do-query
   check-devices
   show-devices
;

: setup-shutdown ( -- )
  f7 ioarcb 42 + c!  0 ioarcb 48 + l!  0 ioarcb 44 + l! ;
: do-shutdown ( -- )  -1 1 0 0 setup-ioarcb  setup-shutdown  do-request ;

: open  true ;
: close ;

: start ['] do-it CATCH IF cr ." Citrine disabled" ELSE make-subnodes THEN ;

cr start cr cr
