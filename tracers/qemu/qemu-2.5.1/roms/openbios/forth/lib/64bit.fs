\ 
\ Copyright (C) 2009 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ Implementation of IEEE Draft Std P1275.6/D5
\ Standard for Boot (Initialization Configuration) Firmware
\ 64 Bit Extensions


cell /x = constant 64bit?

64bit? [IF] 

: 32>64 ( 32bitsigned -- 64bitsigned )
  dup 80000000 and if		\ is it negative?
    ffffffff00000000 or		\ then set all high bits
  then
;

: 64>32 ( 64bitsigned -- 32bitsigned )
  h# ffffffff and
;

: lxjoin ( quad.lo quad.hi -- o )
  d# 32 lshift or
;

: wxjoin ( w.lo w.2 w.3 w.hi -- o )
  wljoin >r wljoin r> lxjoin
;

: bxjoin ( b.lo b.2 b.3 b.4 b.5 b.6 b.7 b.hi -- o )
  bljoin >r bljoin r> lxjoin
;

: <l@ ( qaddr -- n )
  l@ 32>64
;

: unaligned-x@ ( addr - o )
  dup la1+ unaligned-l@ 64>32 swap unaligned-l@ 64>32 lxjoin
;

: unaligned-x! ( o oaddr -- )
  >r dup d# 32 rshift r@ unaligned-l!
  h# ffffffff and r> la1+ unaligned-l!
;
  
: x@ ( oaddr -- o )
  unaligned-x@ \ for now
;

: x! ( o oaddr -- )
  unaligned-x! \ for now
;

: (rx@) ( oaddr - o )
  x@
;

: (rx!) ( o oaddr -- )
  x!
;

: x, ( o -- )
  here /x allot x!
;

: /x* ( nu1 -- nu2 )
  /x *
;

: xa+ ( addr1 index -- addr2 )
  /x* +
;

: xa1+ ( addr1 -- addr2 )
  /x +
;

: xlsplit ( o -- quad.lo quad.hi )
  dup h# ffffffff and swap d# 32 rshift
;

: xwsplit ( o -- w.lo w.2 w.3 w.hi )
  xlsplit >r lwsplit r> lwsplit
;

: xbsplit ( o -- b.lo b.2 b.3 b.4 b.5 b.6 b.7 b.hi )
  xlsplit >r lbsplit r> lbsplit
;

: xlflip ( oct1 -- oct2 )
  xlsplit swap lxjoin
;

: xlflips ( oaddr len -- )
  bounds ?do 
    i unaligned-x@ xlflip i unaligned-x!
  /x +loop
;

: xwflip ( oct1 -- oct2 )
  xlsplit lwflip swap lwflip lxjoin
;

: xwflips ( oaddr len -- )
  bounds ?do
    i unaligned-x@ xwflip i unaligned-x! /x
  +loop
;

: xbflip ( oct1 -- oct2 )
  xlsplit lbflip swap lbflip lxjoin
;

: xbflips ( oaddr len -- )
  bounds ?do
    i unaligned-x@ xbflip i unaligned-x!
  /x +loop
;

\ : b(lit) b(lit) 32>64 ;

[THEN]
