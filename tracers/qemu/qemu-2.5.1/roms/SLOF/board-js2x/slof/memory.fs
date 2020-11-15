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

\ The /memory node.

\ See 3.7.6.
new-device

s" memory" 2dup device-name device-type

: mem-size-u3  20000000 ;
: (mem-size-u4) ( # -- size )
  4 lshift f8002200 + rl@ dup 1 and 0= IF drop 0 EXIT THEN
  dup c000 and e rshift over 3000 and c rshift + 10000000 swap lshift
  swap 2 and 0= IF 2* THEN ;
: mem-size-u4  0 4 0 DO i (mem-size-u4) + LOOP ;
: mem-size   u3? IF mem-size-u3 THEN  u4? IF mem-size-u4 THEN ;
: mem-speed-u4  f8000800 rl@ 12 rshift 7 and 4 + d# 200 * 3 / ;
: mem-speed-u3  f8000f60 rl@ c rshift f and d# 100 * 3 / ;
: mem-speed  u3? IF mem-speed-u3 THEN  u4? IF mem-speed-u4 THEN ;


: encode-our-reg
  0 encode-int 0 encode-int+
  mem-size dup >r 80000000 > IF
  0 encode-int+ 80000000 encode-int+
  1 encode-int+ 0 encode-int+ r> 80000000 - >r THEN
  r@ 20 rshift encode-int+ r> ffffffff and encode-int+ ;
encode-our-reg s" reg" property
0  mem-size release	\ Make our memory available


: mem-report
  base @ decimal mem-size 1e rshift 0 .r
  mem-size 3fffffff and IF ." .5" THEN ."  GB of RAM @ "
  mem-speed . ." MHz" base ! ;

get-node memnode !

: open  true ;
: close ;

finish-device
