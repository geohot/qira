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


new-device

s" i2c" 2dup device-name device-type
s" u4-i2c" compatible

0 encode-int  f8001000 encode-int+
0 encode-int+     1000 encode-int+ s" reg" property

: >i2c  f8001000 + ;
: i2c@  >i2c rl@ ;
: i2c!  >i2c rl! ;

: .i2c  80 0 DO i i2c@ . 10 +LOOP ;

\ 0 mode  1 ctrl  2 stat  3 isr  4 ier  5 addr  6 suba  7 data
\ 8 rev  9 risetime  a bittime

\ 0 mode: 08
\ 1 ctrl: 8 = start  4 = stop  2 = xaddr  1 = aak
\ 2 stat: 2 = lastaak  1 = busy
\ 3 isr: 8 = istart  4 = istop  2 = iaddr  1 = idata
\ 4 ier: --
\ 5 addr: a1..a7
\ 6 suba: offset
\ 7 data: data

: i2c-addr ( addr -- )  50 i2c!  2 10 i2c!  BEGIN 30 i2c@ 2 and UNTIL ;
: i2c-subaddr ( suba -- )  60 i2c! ;
: i2c-stop ( -- )  BEGIN 30 i2c@ dup 30 i2c! 4 and UNTIL ;
: i2c-nak? ( -- failed? )  20 i2c@ 2 and 0= dup IF i2c-stop THEN ;
: i2c-short? ( -- failed? )  30 i2c@ 4 and 0<> dup IF 0 10 i2c! i2c-stop THEN ;
: i2c-aak-if-more ( n -- )  1 <> 1 and 10 i2c! ;

: (read) ( buf len addr -- error? )
  1 or i2c-addr  i2c-nak? IF 2drop true EXIT THEN
  dup i2c-aak-if-more  2 30 i2c!
  BEGIN
  30 i2c@ 1 and IF
    1- >r 70 i2c@ over c! char+ r>
    dup 0= IF i2c-stop 2drop false EXIT THEN
    dup i2c-aak-if-more 1 30 i2c! THEN
  i2c-short? IF 2drop true EXIT THEN
  AGAIN ;

: i2c-read ( buf len addr -- error? )
  4 0 i2c!  (read) ;
: i2c-sub-read ( buf len addr suba -- error? )
  c 0 i2c!  i2c-subaddr  (read) ;

: i2c-write ( buf len addr -- error? )
  4 0 i2c!  i2c-addr  i2c-nak? IF 2drop true EXIT THEN
  over c@ 70 i2c!  2 30 i2c!
  BEGIN
  30 i2c@ 1 and IF
    1- >r char+ r> i2c-nak? IF 2drop true EXIT THEN
    dup 0= IF 4 10 i2c! i2c-stop nip EXIT THEN
    over c@ 70 i2c!  1 30 i2c! THEN
  i2c-short? IF 2drop true EXIT THEN
  AGAIN ;

: open  true ;
: close ;

finish-device
