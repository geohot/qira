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


\ U4 DDR2 memory controller.

cr .( Setting up memory controller...)


\ First, I2C access to the SPDs.

: >i2c  f8001000 + ;
: i2c@  >i2c rl@ ;
: i2c!  >i2c rl! ;

: .i2c  80 0 DO i i2c@ . 10 +LOOP ;

: i2c-addr ( addr -- )  50 i2c!  2 10 i2c!  BEGIN 30 i2c@ 2 and UNTIL ;
: i2c-addr-subaddr ( addr suba -- )  60 i2c! i2c-addr ;
: i2c-stop ( -- )  BEGIN 30 i2c@ dup 30 i2c! 4 and UNTIL ;
: i2c-nak? ( -- failed? )  20 i2c@ 2 and 0= dup IF i2c-stop THEN ;
: i2c-short? ( -- failed? )  30 i2c@ 4 and 0<> dup IF 0 10 i2c! i2c-stop THEN ;
: i2c-aak-if-more ( n -- )  1 <> 1 and 10 i2c! ;

: i2c-sub-read ( buf len addr suba -- error? )
  c 0 i2c!  >r 1 or r> i2c-addr-subaddr  i2c-nak? IF 2drop true EXIT THEN
  dup i2c-aak-if-more  2 30 i2c!
  BEGIN
  30 i2c@ 1 and IF
    1- >r 70 i2c@ over c! char+ r>
    dup 0= IF i2c-stop 2drop false EXIT THEN
    dup i2c-aak-if-more 1 30 i2c! THEN
  i2c-short? IF 2drop true EXIT THEN
  AGAIN ;


\ What slots are filled with working memory (bitmask).

f VALUE dimms-valid
: dimm-invalid  1 swap lshift invert dimms-valid and to dimms-valid ;
: dimm-invalid  dup dimm-invalid 2 xor dimm-invalid ; \ DIMMs are paired
: dimm-valid?  1 swap lshift dimms-valid and ;
: dimm(  +comp postpone 4 postpone 0 postpone DO
               postpone i postpone dimm-valid? postpone IF ; immediate
: )dimm  postpone THEN postpone LOOP -comp ; immediate


\ The data from the SPDs.

CREATE spds 100 allot
: spd@ ( dimm# off -- value ) swap 40 * + spds + c@ ;

CREATE addresses a0 c, a4 c, a2 c, a6 c,
dimm( spds i 40 * + 40 addresses i + c@ 0 i2c-sub-read IF i dimm-invalid THEN )dimm


\ Accessors.

: spd>rows  3 spd@ ;
: spd>cols  4 spd@ ;
: spd>ranks 5 spd@ 7 and 1+ ;
: spd>width d spd@ ;
: spd>banks 11 spd@ ;
: spd>cas   12 spd@ ; \ bit mask of allowable CAS latencies
: spd>trp   1b spd@ ; \ in units of 0.25 ns
: spd>trrd  1c spd@ ; \ in units of 0.25 ns
: spd>trcd  1d spd@ ; \ in units of 0.25 ns
: spd>tras  1e spd@ ; \ in units of 1 ns
: spd>twr   24 spd@ ; \ in units of 0.25 ns
: spd>twtr  25 spd@ ; \ in units of 0.25 ns
: spd>trtp  26 spd@ ; \ in units of 0.25 ns
: spd>trc   29 spd@ ; \ in units of 1 ns  XXX: should also look at byte 28
: spd>trfc  2a spd@ ; \ in units of 1 ns  XXX: should also look at byte 28

cr .( rows cols ranks width banks trp trrd trcd tras twr twtr trtp trc trfc)
cr .( =====================================================================)
decimal
dimm( cr
i spd>rows  4 .r  i spd>cols  5 .r  i spd>ranks 6 .r  i spd>width 6 .r
i spd>banks 6 .r  i spd>trp   4 .r  i spd>trrd  5 .r  i spd>trcd  5 .r
i spd>tras  5 .r  i spd>twr   4 .r  i spd>twtr  5 .r  i spd>trtp  5 .r
i spd>trc   4 .r  i spd>trfc  5 .r
)dimm
hex

ff dimm( i spd>cas and )dimm CONSTANT cl-supported
: max-cl  -1 swap 8 0 DO dup 1 and IF nip i swap THEN u2/ LOOP drop ;
cl-supported max-cl VALUE cl

: tck>60*ns dup f and swap 4 rshift a * over + 6 * swap CASE
            a OF 2d - ENDOF b OF 2e - ENDOF c OF 20 - ENDOF d OF 21 - ENDOF
            ENDCASE ;
: cl>tck  0 spd>cas max-cl swap -
          CASE 0 OF 9 ENDOF 1 OF 17 ENDOF 2 OF 19 ENDOF
          true ABORT" No supported CAS latency for this DIMM" ENDCASE
          0 swap spd@ tck>60*ns ;

: spd>min-tck  dup spd>cas max-cl cl -
               CASE 0 OF 9 ENDOF 1 OF 17 ENDOF 2 OF 19 ENDOF
               true ABORT" No supported CAS latency for this DIMM" ENDCASE
               spd@ tck>60*ns ;
: spd>max-tck  2b spd@ tck>60*ns ;

: .tck  base @ >r decimal dup d# 60 / 0 .r [char] . emit
        d# 60 mod d# 1000 * d# 60 / 3 0.r ." ns" r> base ! ;

cr .( CAS latencies supported: )
8 0 DO cl-supported 1 i lshift and IF i . THEN LOOP

\ Find the lowest CL at the highest tCK.
8 0 DO cl-supported 1 i lshift and IF cl cl>tck i cl>tck = IF
       i to cl LEAVE THEN THEN LOOP

.( -- using ) cl .


0 dimm( i spd>min-tck max )dimm  CONSTANT tck
dimm( i spd>max-tck tck < IF i dimm-invalid THEN )dimm
cr .( tCK is ) tck .tck


0 CONSTANT al
cl al + CONSTANT rl
rl 1- CONSTANT wl

: //  dup >r 1- + r> / ; \ round up
0 spd>tras d# 60 * tck // CONSTANT tras
0 spd>trtp d# 15 * tck // CONSTANT trtp
0 spd>twr  d# 15 * tck // CONSTANT twr
0 spd>trp  d# 15 * tck // CONSTANT trp
0 spd>trrd d# 15 * tck // CONSTANT trrd
0 spd>trrd d# 60 * tck // CONSTANT 4*trrd
0 spd>trcd d# 15 * tck // CONSTANT trcd
0 spd>trc  d# 60 * tck // CONSTANT trc
0 spd>twtr d# 15 * tck // CONSTANT twtr

: spd>memmd
  >r r@ spd>rows r@ spd>cols +
  r@ spd>banks 2log + 4 * r> spd>width 2log 3 * + 6c - ;
: dimm-group-size ( dimm# -- size )
  >r r@ spd>rows r@ spd>cols + 1 swap lshift
  r@ spd>banks * r> spd>ranks * 10 * ;
VARIABLE start-address
VARIABLE was-prev-big
: assign-dimm-group ( dimm# -- config-value )
  dup dimm-valid? 0= IF drop 0 EXIT THEN
  \ MemMd, enable, single-sided or not
  dup spd>memmd c lshift 1 or over spd>ranks 1 = IF 2 or THEN 
cr ." ---> " dup .
>r
  dimm-group-size start-address @ 2dup + rot ( start end size )
  80000000 > IF
    dup 1000000000 < IF dup 4 rshift ELSE 08000000 THEN r> or >r \ Add2G
    over 0<>        IF over c rshift ELSE 00080000 THEN r> or >r \ Sub2G
    was-prev-big on
  ELSE
    was-prev-big @ IF 80000000 + swap 80000000 + swap THEN r> 08080000 or >r
    was-prev-big off
  THEN
  swap 18 rshift r> or >r \ start address
  dup 80000000 = IF drop 100000000 THEN start-address ! r> ;


\ Now set the frequency in the memory controller
d# 1800 tck / 4 - 12 lshift 33c or f8000800 rl!
f8000860 rl@ 80000000 or f8000860 rl!  10000 0 DO LOOP

: mc!  f8002000 + rl! ;
: mc@  f8002000 + rl@ ;


\ memory timing regs (state machine)

tras 2-
5 lshift al trtp + 2- or
5 lshift wl twr + or
5 lshift trp 2- or
5 lshift trp 2- 0 spd>banks 8 = IF 1+ THEN or
7 lshift 030 mc!

al trtp + trp + 2-
5 lshift cl al + twr + trp + 1- or
5 lshift trrd 2- or
5 lshift trc 2- or
5 lshift trcd 2- or
5 lshift 4*trrd or
2 lshift 040 mc!

0
5 lshift 1 or
5 lshift 1 or
5 lshift cl 1- twtr + or
5 lshift 1 or
5 lshift 1 or
2 lshift 050 mc!

0
5 lshift 1 or
5 lshift 1 or
5 lshift 2 or
5 lshift 2 or
5 lshift 2 or
2 lshift 060 mc! \ XXX joerg has different setting

cl 3 = IF 30801800 ( 30800d00 ) 070 mc! \ XXX memory refresh
ELSE 41002000 070 mc! THEN

\ memory size regs

1 dimm-group-size 0 dimm-group-size > 1 0 rot IF swap THEN \ biggest first
assign-dimm-group 200 mc!
assign-dimm-group 210 mc!
0 220 mc! 0 230 mc!





\ arbiter tunables
\ 40041040 270 mc!
04041040 270 mc!
50000000 280 mc!
\ a0a00000 290 mc! \ a0000000 might be faster
00000000 290 mc!
\ 20020820 2a0 mc!
04020822 2a0 mc!
00000000 2b0 mc!
\ 30413cc7 2c0 mc! \ have to calculate the low five bits
30413dc5 2c0 mc!
\ cl 3 = IF 76000050 2d0 mc!  70000000 2e0 mc! ELSE
cl 3 = IF 75000050 2d0 mc!  70000000 2e0 mc! ELSE
    b8002080 2d0 mc!  b0000000 2e0 mc! THEN
\ Should test for something else really



cl 3 = IF 00006000 890 mc!  00006000 8a0 mc! ELSE
          00006500 890 mc!  00006500 8a0 mc! THEN

cl 3 = IF 1e008a8a ELSE 31000000 THEN
dup 800 mc! dup 810 mc! dup 820 mc! dup 830 mc!
dup 900 mc! dup 910 mc! dup 920 mc! dup 930 mc! dup 980 mc!
dup a00 mc! dup a10 mc! dup a20 mc! dup a30 mc!
dup b00 mc! dup b10 mc! dup b20 mc! dup b30 mc!     b80 mc!

\ 0 8d0 mc!  0 9d0 mc!  0 ad0 mc!  0 bd0 mc!
61630000 8d0 mc!
61630000 9d0 mc!
52510000 ad0 mc!
434e0000 bd0 mc!

a0200400 100 mc!
80020000 110 mc!
80030000 120 mc!
80010404 130 mc!
cl 3 = IF
8000153a 140 mc! ELSE
8000174a 140 mc! THEN
a0200400 150 mc!
\ 92000000 160 mc!
\ 92000000 170 mc!
\ 91300000 160 mc!
\ 91300000 170 mc!
91800000 160 mc!
91800000 170 mc!
cl 3 = IF
8ff0143a 180 mc! ELSE
8ff0164a 180 mc! THEN
80010784 190 mc!
80010404 1a0 mc!
0 1b0 mc!  0 1c0 mc!  0 1d0 mc!  0 1e0 mc!  0 1f0 mc!

cl 3 = IF
143a 0c0 mc! ELSE
164a 0c0 mc! THEN
0404 0d0 mc!

\ after this point, setup is common for all speeds and sizes of dimms (sort of)

60000000 3a0 mc!

0 840 mc!  0 850 mc!  0 860 mc!  0 870 mc!
0 940 mc!  0 950 mc!  0 960 mc!  0 970 mc!  0 990 mc!
0 a40 mc!  0 a50 mc!  0 a60 mc!  0 a70 mc!
0 b40 mc!  0 b50 mc!  0 b60 mc!  0 b70 mc!  0 b90 mc!

0 880 mc!

001a4000 9a0 mc!

84800000 500 mc!

10000 0 DO LOOP

80000000 b0 mc!  BEGIN b0 mc@ 40000000 and UNTIL

0 300 mc!  0 310 mc!

80000000 440 mc!
0 410 mc!  27fffffc 420 mc!
fedcba98 430 mc!
c0000000 400 mc!  BEGIN 400 mc@ c0000000 and 0= UNTIL

cr .( mem done)
