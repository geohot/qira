\ *****************************************************************************
\ * Copyright (c) 2004, 2014 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

51 CONSTANT nvram-partition-type-cpulog
\ types 53-55 are omitted because they have been used for
\ storing binary tables in the past
60 CONSTANT nvram-partition-type-sas
61 CONSTANT nvram-partition-type-sms
6e CONSTANT nvram-partition-type-debug
6f CONSTANT nvram-partition-type-history
70 CONSTANT nvram-partition-type-common
7f CONSTANT nvram-partition-type-freespace
a0 CONSTANT nvram-partition-type-linux

: rztype ( str len -- ) \ stop at zero byte, read with nvram-c@
   0 DO
      dup i + nvram-c@ ?dup IF ( str char )
         emit
      ELSE                     ( str )
         drop UNLOOP EXIT
      THEN
   LOOP
;

create tmpStr 500 allot
: rzcount ( zstr -- str len )
   dup tmpStr >r BEGIN
      dup nvram-c@ dup r> dup 1+ >r c!
   WHILE
      char+
   REPEAT
   r> drop over - swap drop tmpStr swap
;

: calc-header-cksum ( offset -- cksum )
   dup nvram-c@
   10 2 DO
      over I + nvram-c@ +
   LOOP
   wbsplit + nip
;

: bad-header? ( offset -- flag )
   dup 2+ nvram-w@        ( offset length )
   0= IF                  ( offset )
      drop true EXIT      ( )
   THEN
   dup calc-header-cksum  ( offset checksum' )
   swap 1+ nvram-c@       ( checksum ' checksum )
   <>                     ( flag )
;

: .header ( offset -- )
   cr                         ( offset )
   dup bad-header? IF         ( offset )
      ."   BAD HEADER -- trying to print it anyway" cr
   THEN
   space                      ( offset )
   \ print type
   dup nvram-c@ 2 0.r         ( offset )
   space space                ( offset )
   \ print length
   dup 2+ nvram-w@ 10 * 5 .r  ( offset )
   space space                ( offset )
   \ print name
   4 + 0c rztype              ( )
;

: .headers ( -- )
   cr cr ." Type  Size  Name"
   cr ." ========================"
   0 BEGIN                      ( offset )
      dup nvram-c@              ( offset type )
   WHILE
      dup .header               ( offset )
      dup 2+ nvram-w@ 10 * +    ( offset offset' )
      dup nvram-size < IF       ( offset )
      ELSE
	 drop EXIT              ( )
      THEN
   REPEAT
   drop                         ( )
   cr cr
;

: reset-nvram ( -- )
   internal-reset-nvram
;

: dump-partition     ['] nvram-c@      1 (dump) ;

: type-no-zero ( addr len -- )
   0 DO
      dup I + dup nvram-c@ 0= IF drop ELSE nvram-c@ emit THEN
   LOOP
   drop
;

: type-no-zero-part ( from-str cnt-str addr len )
   0 DO
      dup i + dup nvram-c@ 0= IF
         drop
      ELSE
         ( from-str cnt-str addr addr+i )
         ( from-str==0 AND cnt-str > 0 )
         3 pick 0= 3 pick 0 > AND IF
            dup 1 type-no-zero
         THEN

         nvram-c@ a = IF
            2 pick 0= IF
               over 1- 0 max
               rot drop swap
            THEN
            2 pick 1- 0 max
            3 roll drop rot rot
            ( from-str-- cnt-str-- addr addr+i )
         THEN
      THEN
   LOOP
   drop
;

: (dmesg-prepare) ( base-addr -- base-addr' addr len act-off )
   10 - \ go back to header
   dup 14 + nvram-l@ dup >r
   ( base-addr act-off ) ( R: act-off )
   over over over + swap 10 + nvram-w@ + >r
   ( base-addr act-off ) ( R:  act-off nvram-act-addr )
   over 2 + nvram-w@ 10 * swap - over swap
   ( base-addr base-addr start-size ) ( R:  act-off nvram-act-addr )
   r> swap rot 10 + nvram-w@ - r>
;

: .dmesg ( base-addr -- )
   (dmesg-prepare) >r
   ( base-addr addr len )
   cr type-no-zero
   ( base-addr ) ( R: act-off )
   dup 10 + nvram-w@ + r> type-no-zero
;

: .dmesg-part ( from-str cnt-str base-addr -- )
   (dmesg-prepare) >r
   ( from-str cnt-str base-addr addr len )
   >r >r -rot r> r>
   ( base-addr from-str cnt-str addr len )
   cr type-no-zero-part rot
   ( base-addr ) ( R: act-off )
   dup 10 + nvram-w@ + r> type-no-zero-part
;

: dmesg-part ( from-str cnt-str -- left-from-str left-cnt-str )
   2dup
   s" ibm,CPU0log" get-named-nvram-partition IF
      2drop EXIT
   THEN
   drop .dmesg-part nip nip
;

: dmesg2 ( -- )
   s" ibm,CPU1log" get-named-nvram-partition IF
      ." No log partition." cr EXIT
   THEN
   drop .dmesg
;

: dmesg ( -- )
   s" ibm,CPU0log" get-named-nvram-partition IF
      ." No log partition." cr EXIT
   THEN
   drop .dmesg
;
