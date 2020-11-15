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


\ Hex dump facilities.

1 VALUE /dump
' c@ VALUE 'dump
0 VALUE dump-first
0 VALUE dump-last
0 VALUE dump-cur
: .char ( c -- )  dup bl 7f within 0= IF drop [char] . THEN emit ;
: dump-line ( -- )
  cr dump-cur dup 8 0.r [char] : emit 10 /dump / 0 DO
  space dump-cur dump-first dump-last within IF
  dump-cur 'dump execute /dump 2* 0.r ELSE
  /dump 2* spaces THEN dump-cur /dump + to dump-cur LOOP
  /dump 1 <> IF drop EXIT THEN
  to dump-cur 2 spaces
  10 0 DO dump-cur dump-first dump-last within IF
  dump-cur 'dump execute .char ELSE space THEN dump-cur 1+ to dump-cur LOOP ;
: (dump) ( addr len reader size -- )
  to /dump to 'dump bounds /dump negate and to dump-first to dump-last
  dump-first f invert and to dump-cur
  base @ hex BEGIN dump-line dump-cur dump-last >= UNTIL base ! ;
: du ( -- )  dump-last 100 'dump /dump (dump) ;
: dump     ['] c@      1 (dump) ;
: wdump    ['] w@      2 (dump) ;
: ldump    ['] l@      4 (dump) ;
: xdump    ['] x@      8 (dump) ;
: rdump    ['] rb@     1 (dump) ;
\ : iodump   ['] io-c@   1 (dump) ;
\ : siodump  ['] siocfg@ 1 (dump) ;
