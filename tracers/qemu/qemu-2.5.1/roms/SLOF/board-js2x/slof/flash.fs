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

ff000000 CONSTANT flash-addr

: >flash  flash-addr + ;
: flash@  >flash rb@ ;
: flash!  >flash rb! ;
: wait-for-flash-ready  BEGIN 0 flash@ 80 and UNTIL ;
: erase-flash-block ( offset -- )
  cr dup 8 .r ."  Erasing..."
  20 over flash! d0 swap flash! wait-for-flash-ready ;
: write-flash ( data offset -- )
  40 over flash! flash! wait-for-flash-ready ;
: write-flash-buffer ( addr offset -- )
  e8 over flash!  wait-for-flash-ready  1f over flash!
  20 0 DO over i + c@ over i + flash! LOOP
  d0 over flash! wait-for-flash-ready 2drop ;
: write-flash-block ( addr offset -- ) \ always writes 128kB!
  ."  Writing..."
  20000 0 DO over i + over i + write-flash-buffer 20 +LOOP 2drop
  ."  Done." ;
: flash ( addr offset size -- )
  BEGIN dup 0 > WHILE >r dup erase-flash-block 2dup write-flash-block
  >r 20000 + r> 20000 + r> 20000 - REPEAT drop 2drop -1 0 flash! ;

: flash-it  get-load-base 0 e0000  flash ;
: flash4    get-load-base 0 400000 flash ;

\ for update-flash
: flash-image-size  ( addr -- size )  30 + rx@  ;
