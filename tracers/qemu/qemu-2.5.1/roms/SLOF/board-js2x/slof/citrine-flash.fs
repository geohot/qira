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


\ we do all flash accesses as 8-bit

9f000000 CONSTANT citrine-flash-addr

: >citrine-flash  citrine-flash-addr + ;
: citrine-flash@  >citrine-flash rb@ ;
: citrine-flash!  >citrine-flash rb! ;
: wait-for-citrine-flash-ready  BEGIN 0 citrine-flash@ 80 and UNTIL ;
: erase-citrine-flash-block ( offset -- )
  cr dup 8 .r ."  Erasing..."
  20 over citrine-flash! d0 swap citrine-flash! wait-for-citrine-flash-ready ;
: write-citrine-flash ( data offset -- )
  over ff = IF 2drop EXIT THEN
  40 over citrine-flash! citrine-flash! wait-for-citrine-flash-ready ;
: write-citrine-flash-block ( addr offset -- ) \ always writes 128kB!
  ."  Writing..."
  20000 0 DO over i + c@ over i + write-citrine-flash LOOP 2drop
  ."  Done." ;
: citrine-flash ( addr offset size -- )
  BEGIN dup 0 > WHILE >r dup erase-citrine-flash-block
  2dup write-citrine-flash-block >r 20000 + r> 20000 + r> 20000 - REPEAT
  drop 2drop -1 0 citrine-flash! ;

