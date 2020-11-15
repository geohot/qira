\ From: John Hayes S1I
\ Subject: tester.fr
\ Date: Mon, 27 Nov 95 13:10:09 PST  

\ (C) 1995 JOHNS HOPKINS UNIVERSITY / APPLIED PHYSICS LABORATORY
\ MAY BE DISTRIBUTED FREELY AS LONG AS THIS COPYRIGHT NOTICE REMAINS.
\ VERSION 1.1

HEX

\ switch output of hex values to capital letters
true to capital-hex?


\ SET THE FOLLOWING FLAG TO TRUE FOR MORE VERBOSE OUTPUT; THIS MAY
\ ALLOW YOU TO TELL WHICH TEST CAUSED YOUR SYSTEM TO HANG.

VARIABLE VERBOSE
   FALSE VERBOSE !

: EMPTY-STACK	\ ( ... -- ) EMPTY STACK: HANDLES UNDERFLOWED STACK TOO.
   DEPTH ?DUP IF DUP 0< IF NEGATE 0 DO 0 LOOP ELSE 0 DO DROP LOOP THEN THEN ;

: ERROR		\ ( C-ADDR U -- ) DISPLAY AN ERROR MESSAGE FOLLOWED BY
		\ THE LINE THAT HAD THE ERROR.
   \ TYPE SOURCE TYPE CR			\ DISPLAY LINE CORRESPONDING TO ERROR

   \ FIXME beginagain wants the following for output:
   TYPE SOURCE drop span @ TYPE CR	\ DISPLAY LINE CORRESPONDING TO ERROR
   EMPTY-STACK				\ THROW AWAY EVERY THING ELSE
   -99 SYS-DEBUG                        \ MAKE BEGINAGAIN BOOTSTRAP FAIL.
;

VARIABLE ACTUAL-DEPTH			\ STACK RECORD
CREATE ACTUAL-RESULTS 20 CELLS ALLOT

: {		\ ( -- ) SYNTACTIC SUGAR.
   ;

: ->		\ ( ... -- ) RECORD DEPTH AND CONTENT OF STACK.
   DEPTH DUP ACTUAL-DEPTH !		\ RECORD DEPTH
   ?DUP IF				\ IF THERE IS SOMETHING ON STACK
      0 DO ACTUAL-RESULTS I CELLS + ! LOOP \ SAVE THEM
   THEN ;

: }		\ ( ... -- ) COMPARE STACK (EXPECTED) CONTENTS WITH SAVED
		\ (ACTUAL) CONTENTS.
   DEPTH ACTUAL-DEPTH @ = IF		\ IF DEPTHS MATCH
      DEPTH ?DUP IF			\ IF THERE IS SOMETHING ON THE STACK
         0 DO				\ FOR EACH STACK ITEM
	    ACTUAL-RESULTS I CELLS + @	\ COMPARE ACTUAL WITH EXPECTED
	    <> IF S" INCORRECT RESULT: " ERROR LEAVE THEN
	 LOOP
      THEN
   ELSE					\ DEPTH MISMATCH
      S" WRONG NUMBER OF RESULTS: " ERROR
   THEN ;

: TESTING	\ ( -- ) TALKING COMMENT.
   SOURCE VERBOSE @
   IF DUP >R TYPE CR R> >IN !
   ELSE >IN ! DROP
   THEN 
   ;

\ From: John Hayes S1I
\ Subject: core.fr
\ Date: Mon, 27 Nov 95 13:10

\ (C) 1995 JOHNS HOPKINS UNIVERSITY / APPLIED PHYSICS LABORATORY
\ MAY BE DISTRIBUTED FREELY AS LONG AS THIS COPYRIGHT NOTICE REMAINS.
\ VERSION 1.2
\ THIS PROGRAM TESTS THE CORE WORDS OF AN ANS FORTH SYSTEM.
\ THE PROGRAM ASSUMES A TWO'S COMPLEMENT IMPLEMENTATION WHERE
\ THE RANGE OF SIGNED NUMBERS IS -2^(N-1) ... 2^(N-1)-1 AND
\ THE RANGE OF UNSIGNED NUMBERS IS 0 ... 2^(N)-1.
\ I HAVEN'T FIGURED OUT HOW TO TEST KEY, QUIT, ABORT, OR ABORT"...
\ I ALSO HAVEN'T THOUGHT OF A WAY TO TEST ENVIRONMENT?...

TESTING CORE WORDS
HEX

\ ------------------------------------------------------------------------
TESTING BASIC ASSUMPTIONS

{ -> }					\ START WITH CLEAN SLATE
( TEST IF ANY BITS ARE SET; ANSWER IN BASE 1 )
{ : BITSSET? IF 0 0 ELSE 0 THEN ; -> }
{  0 BITSSET? -> 0 }		( ZERO IS ALL BITS CLEAR )
{  1 BITSSET? -> 0 0 }		( OTHER NUMBER HAVE AT LEAST ONE BIT )
{ -1 BITSSET? -> 0 0 }

\ ------------------------------------------------------------------------
TESTING BOOLEANS: INVERT AND OR XOR

{ 0 0 AND -> 0 }
{ 0 1 AND -> 0 }
{ 1 0 AND -> 0 }
{ 1 1 AND -> 1 }

{ 0 INVERT 1 AND -> 1 }
{ 1 INVERT 1 AND -> 0 }

0	 CONSTANT 0S
0 INVERT CONSTANT 1S

{ 0S INVERT -> 1S }
{ 1S INVERT -> 0S }

{ 0S 0S AND -> 0S }
{ 0S 1S AND -> 0S }
{ 1S 0S AND -> 0S }
{ 1S 1S AND -> 1S }

{ 0S 0S OR -> 0S }
{ 0S 1S OR -> 1S }
{ 1S 0S OR -> 1S }
{ 1S 1S OR -> 1S }

{ 0S 0S XOR -> 0S }
{ 0S 1S XOR -> 1S }
{ 1S 0S XOR -> 1S }
{ 1S 1S XOR -> 0S }

\ ------------------------------------------------------------------------
TESTING 2* 2/ LSHIFT RSHIFT

( WE TRUST 1S, INVERT, AND BITSSET?; WE WILL CONFIRM RSHIFT LATER )
1S 1 RSHIFT INVERT CONSTANT MSB
{ MSB BITSSET? -> 0 0 }

{ 0S 2* -> 0S }
{ 1 2* -> 2 }
{ 4000 2* -> 8000 }
{ 1S 2* 1 XOR -> 1S }
{ MSB 2* -> 0S }

{ 0S 2/ -> 0S }
{ 1 2/ -> 0 }
{ 4000 2/ -> 2000 }
{ 1S 2/ -> 1S }				\ MSB PROPOGATED
{ 1S 1 XOR 2/ -> 1S }
{ MSB 2/ MSB AND -> MSB }

{ 1 0 LSHIFT -> 1 }
{ 1 1 LSHIFT -> 2 }
{ 1 2 LSHIFT -> 4 }
{ 1 F LSHIFT -> 8000 }			\ BIGGEST GUARANTEED SHIFT
{ 1S 1 LSHIFT 1 XOR -> 1S }
{ MSB 1 LSHIFT -> 0 }

{ 1 0 RSHIFT -> 1 }
{ 1 1 RSHIFT -> 0 }
{ 2 1 RSHIFT -> 1 }
{ 4 2 RSHIFT -> 1 }
{ 8000 F RSHIFT -> 1 }			\ BIGGEST
{ MSB 1 RSHIFT MSB AND -> 0 }		\ RSHIFT ZERO FILLS MSBS
{ MSB 1 RSHIFT 2* -> MSB }

\ ------------------------------------------------------------------------
TESTING COMPARISONS: 0= = 0< < > U< MIN MAX
0 INVERT			CONSTANT MAX-UINT
0 INVERT 1 RSHIFT		CONSTANT MAX-INT
0 INVERT 1 RSHIFT INVERT	CONSTANT MIN-INT
0 INVERT 1 RSHIFT		CONSTANT MID-UINT
0 INVERT 1 RSHIFT INVERT	CONSTANT MID-UINT+1

0S CONSTANT <FALSE>
1S CONSTANT <TRUE>

{ 0 0= -> <TRUE> }
{ 1 0= -> <FALSE> }
{ 2 0= -> <FALSE> }
{ -1 0= -> <FALSE> }
{ MAX-UINT 0= -> <FALSE> }
{ MIN-INT 0= -> <FALSE> }
{ MAX-INT 0= -> <FALSE> }

{ 0 0 = -> <TRUE> }
{ 1 1 = -> <TRUE> }
{ -1 -1 = -> <TRUE> }
{ 1 0 = -> <FALSE> }
{ -1 0 = -> <FALSE> }
{ 0 1 = -> <FALSE> }
{ 0 -1 = -> <FALSE> }

{ 0 0< -> <FALSE> }
{ -1 0< -> <TRUE> }
{ MIN-INT 0< -> <TRUE> }
{ 1 0< -> <FALSE> }
{ MAX-INT 0< -> <FALSE> }

{ 0 1 < -> <TRUE> }
{ 1 2 < -> <TRUE> }
{ -1 0 < -> <TRUE> }
{ -1 1 < -> <TRUE> }
{ MIN-INT 0 < -> <TRUE> }
{ MIN-INT MAX-INT < -> <TRUE> }
{ 0 MAX-INT < -> <TRUE> }
{ 0 0 < -> <FALSE> }
{ 1 1 < -> <FALSE> }
{ 1 0 < -> <FALSE> }
{ 2 1 < -> <FALSE> }
{ 0 -1 < -> <FALSE> }
{ 1 -1 < -> <FALSE> }
{ 0 MIN-INT < -> <FALSE> }
{ MAX-INT MIN-INT < -> <FALSE> }
{ MAX-INT 0 < -> <FALSE> }

{ 0 1 > -> <FALSE> }
{ 1 2 > -> <FALSE> }
{ -1 0 > -> <FALSE> }
{ -1 1 > -> <FALSE> }
{ MIN-INT 0 > -> <FALSE> }
{ MIN-INT MAX-INT > -> <FALSE> }
{ 0 MAX-INT > -> <FALSE> }
{ 0 0 > -> <FALSE> }
{ 1 1 > -> <FALSE> }
{ 1 0 > -> <TRUE> }
{ 2 1 > -> <TRUE> }
{ 0 -1 > -> <TRUE> }
{ 1 -1 > -> <TRUE> }
{ 0 MIN-INT > -> <TRUE> }
{ MAX-INT MIN-INT > -> <TRUE> }
{ MAX-INT 0 > -> <TRUE> }

{ 0 1 U< -> <TRUE> }
{ 1 2 U< -> <TRUE> }
{ 0 MID-UINT U< -> <TRUE> }
{ 0 MAX-UINT U< -> <TRUE> }
{ MID-UINT MAX-UINT U< -> <TRUE> }
{ 0 0 U< -> <FALSE> }
{ 1 1 U< -> <FALSE> }
{ 1 0 U< -> <FALSE> }
{ 2 1 U< -> <FALSE> }
{ MID-UINT 0 U< -> <FALSE> }
{ MAX-UINT 0 U< -> <FALSE> }
{ MAX-UINT MID-UINT U< -> <FALSE> }

{ 0 1 MIN -> 0 }
{ 1 2 MIN -> 1 }
{ -1 0 MIN -> -1 }
{ -1 1 MIN -> -1 }
{ MIN-INT 0 MIN -> MIN-INT }
{ MIN-INT MAX-INT MIN -> MIN-INT }
{ 0 MAX-INT MIN -> 0 }
{ 0 0 MIN -> 0 }
{ 1 1 MIN -> 1 }
{ 1 0 MIN -> 0 }
{ 2 1 MIN -> 1 }
{ 0 -1 MIN -> -1 }
{ 1 -1 MIN -> -1 }
{ 0 MIN-INT MIN -> MIN-INT }
{ MAX-INT MIN-INT MIN -> MIN-INT }
{ MAX-INT 0 MIN -> 0 }

{ 0 1 MAX -> 1 }
{ 1 2 MAX -> 2 }
{ -1 0 MAX -> 0 }
{ -1 1 MAX -> 1 }
{ MIN-INT 0 MAX -> 0 }
{ MIN-INT MAX-INT MAX -> MAX-INT }
{ 0 MAX-INT MAX -> MAX-INT }
{ 0 0 MAX -> 0 }
{ 1 1 MAX -> 1 }
{ 1 0 MAX -> 1 }
{ 2 1 MAX -> 2 }
{ 0 -1 MAX -> 0 }
{ 1 -1 MAX -> 1 }
{ 0 MIN-INT MAX -> 0 }
{ MAX-INT MIN-INT MAX -> MAX-INT }
{ MAX-INT 0 MAX -> MAX-INT }

\ ------------------------------------------------------------------------
TESTING STACK OPS: 2DROP 2DUP 2OVER 2SWAP ?DUP DEPTH DROP DUP OVER ROT SWAP

{ 1 2 2DROP -> }
{ 1 2 2DUP -> 1 2 1 2 }
{ 1 2 3 4 2OVER -> 1 2 3 4 1 2 }
{ 1 2 3 4 2SWAP -> 3 4 1 2 }
{ 0 ?DUP -> 0 }
{ 1 ?DUP -> 1 1 }
{ -1 ?DUP -> -1 -1 }
{ DEPTH -> 0 }
{ 0 DEPTH -> 0 1 }
{ 0 1 DEPTH -> 0 1 2 }
{ 0 DROP -> }
{ 1 2 DROP -> 1 }
{ 1 DUP -> 1 1 }
{ 1 2 OVER -> 1 2 1 }
{ 1 2 3 ROT -> 2 3 1 }
{ 1 2 SWAP -> 2 1 }

\ ------------------------------------------------------------------------
TESTING >R R> R@

{ : GR1 >R R> ; -> }
{ : GR2 >R R@ R> DROP ; -> }
{ 123 GR1 -> 123 }
{ 123 GR2 -> 123 }
{ 1S GR1 -> 1S }   ( RETURN STACK HOLDS CELLS )

\ ------------------------------------------------------------------------
TESTING ADD/SUBTRACT: + - 1+ 1- ABS NEGATE

{ 0 5 + -> 5 }
{ 5 0 + -> 5 }
{ 0 -5 + -> -5 }
{ -5 0 + -> -5 }
{ 1 2 + -> 3 }
{ 1 -2 + -> -1 }
{ -1 2 + -> 1 }
{ -1 -2 + -> -3 }
{ -1 1 + -> 0 }
{ MID-UINT 1 + -> MID-UINT+1 }

{ 0 5 - -> -5 }
{ 5 0 - -> 5 }
{ 0 -5 - -> 5 }
{ -5 0 - -> -5 }
{ 1 2 - -> -1 }
{ 1 -2 - -> 3 }
{ -1 2 - -> -3 }
{ -1 -2 - -> 1 }
{ 0 1 - -> -1 }
{ MID-UINT+1 1 - -> MID-UINT }

{ 0 1+ -> 1 }
{ -1 1+ -> 0 }
{ 1 1+ -> 2 }
{ MID-UINT 1+ -> MID-UINT+1 }

{ 2 1- -> 1 }
{ 1 1- -> 0 }
{ 0 1- -> -1 }
{ MID-UINT+1 1- -> MID-UINT }

{ 0 NEGATE -> 0 }
{ 1 NEGATE -> -1 }
{ -1 NEGATE -> 1 }
{ 2 NEGATE -> -2 }
{ -2 NEGATE -> 2 }

{ 0 ABS -> 0 }
{ 1 ABS -> 1 }
{ -1 ABS -> 1 }
{ MIN-INT ABS -> MID-UINT+1 }

\ ------------------------------------------------------------------------
TESTING MULTIPLY: S>D * M* UM*

{ 0 S>D -> 0 0 }
{ 1 S>D -> 1 0 }
{ 2 S>D -> 2 0 }
{ -1 S>D -> -1 -1 }
{ -2 S>D -> -2 -1 }
{ MIN-INT S>D -> MIN-INT -1 }
{ MAX-INT S>D -> MAX-INT 0 }

{ 0 0 M* -> 0 S>D }
{ 0 1 M* -> 0 S>D }
{ 1 0 M* -> 0 S>D }
{ 1 2 M* -> 2 S>D }
{ 2 1 M* -> 2 S>D }
{ 3 3 M* -> 9 S>D }
{ -3 3 M* -> -9 S>D }
{ 3 -3 M* -> -9 S>D }
{ -3 -3 M* -> 9 S>D }
{ 0 MIN-INT M* -> 0 S>D }
{ 1 MIN-INT M* -> MIN-INT S>D }
{ 2 MIN-INT M* -> 0 1S }
{ 0 MAX-INT M* -> 0 S>D }
{ 1 MAX-INT M* -> MAX-INT S>D }
{ 2 MAX-INT M* -> MAX-INT 1 LSHIFT 0 }
{ MIN-INT MIN-INT M* -> 0 MSB 1 RSHIFT }
{ MAX-INT MIN-INT M* -> MSB MSB 2/ }
{ MAX-INT MAX-INT M* -> 1 MSB 2/ INVERT }

{ 0 0 * -> 0 }				\ TEST IDENTITIES
{ 0 1 * -> 0 }
{ 1 0 * -> 0 }
{ 1 2 * -> 2 }
{ 2 1 * -> 2 }
{ 3 3 * -> 9 }
{ -3 3 * -> -9 }
{ 3 -3 * -> -9 }
{ -3 -3 * -> 9 }

{ MID-UINT+1 1 RSHIFT 2 * -> MID-UINT+1 }
{ MID-UINT+1 2 RSHIFT 4 * -> MID-UINT+1 }
{ MID-UINT+1 1 RSHIFT MID-UINT+1 OR 2 * -> MID-UINT+1 }

{ 0 0 UM* -> 0 0 }
{ 0 1 UM* -> 0 0 }
{ 1 0 UM* -> 0 0 }
{ 1 2 UM* -> 2 0 }
{ 2 1 UM* -> 2 0 }
{ 3 3 UM* -> 9 0 }

{ MID-UINT+1 1 RSHIFT 2 UM* -> MID-UINT+1 0 }
{ MID-UINT+1 2 UM* -> 0 1 }
{ MID-UINT+1 4 UM* -> 0 2 }
{ 1S 2 UM* -> 1S 1 LSHIFT 1 }
{ MAX-UINT MAX-UINT UM* -> 1 1 INVERT }

\ ------------------------------------------------------------------------
TESTING DIVIDE: FM/MOD SM/REM UM/MOD */ */MOD / /MOD MOD

{ 0 S>D 1 FM/MOD -> 0 0 }
{ 1 S>D 1 FM/MOD -> 0 1 }
{ 2 S>D 1 FM/MOD -> 0 2 }
{ -1 S>D 1 FM/MOD -> 0 -1 }
{ -2 S>D 1 FM/MOD -> 0 -2 }
{ 0 S>D -1 FM/MOD -> 0 0 }
{ 1 S>D -1 FM/MOD -> 0 -1 }
{ 2 S>D -1 FM/MOD -> 0 -2 }
{ -1 S>D -1 FM/MOD -> 0 1 }
{ -2 S>D -1 FM/MOD -> 0 2 }
{ 2 S>D 2 FM/MOD -> 0 1 }
{ -1 S>D -1 FM/MOD -> 0 1 }
{ -2 S>D -2 FM/MOD -> 0 1 }
{  7 S>D  3 FM/MOD -> 1 2 }
{  7 S>D -3 FM/MOD -> -2 -3 }
{ -7 S>D  3 FM/MOD -> 2 -3 }
{ -7 S>D -3 FM/MOD -> -1 2 }
{ MAX-INT S>D 1 FM/MOD -> 0 MAX-INT }
{ MIN-INT S>D 1 FM/MOD -> 0 MIN-INT }
{ MAX-INT S>D MAX-INT FM/MOD -> 0 1 }
{ MIN-INT S>D MIN-INT FM/MOD -> 0 1 }
{ 1S 1 4 FM/MOD -> 3 MAX-INT }
{ 1 MIN-INT M* 1 FM/MOD -> 0 MIN-INT }
{ 1 MIN-INT M* MIN-INT FM/MOD -> 0 1 }
{ 2 MIN-INT M* 2 FM/MOD -> 0 MIN-INT }
{ 2 MIN-INT M* MIN-INT FM/MOD -> 0 2 }
{ 1 MAX-INT M* 1 FM/MOD -> 0 MAX-INT }
{ 1 MAX-INT M* MAX-INT FM/MOD -> 0 1 }
{ 2 MAX-INT M* 2 FM/MOD -> 0 MAX-INT }
{ 2 MAX-INT M* MAX-INT FM/MOD -> 0 2 }
{ MIN-INT MIN-INT M* MIN-INT FM/MOD -> 0 MIN-INT }
{ MIN-INT MAX-INT M* MIN-INT FM/MOD -> 0 MAX-INT }
{ MIN-INT MAX-INT M* MAX-INT FM/MOD -> 0 MIN-INT }
{ MAX-INT MAX-INT M* MAX-INT FM/MOD -> 0 MAX-INT }

{ 0 S>D 1 SM/REM -> 0 0 }
{ 1 S>D 1 SM/REM -> 0 1 }
{ 2 S>D 1 SM/REM -> 0 2 }
{ -1 S>D 1 SM/REM -> 0 -1 }
{ -2 S>D 1 SM/REM -> 0 -2 }
{ 0 S>D -1 SM/REM -> 0 0 }
{ 1 S>D -1 SM/REM -> 0 -1 }
{ 2 S>D -1 SM/REM -> 0 -2 }
{ -1 S>D -1 SM/REM -> 0 1 }
{ -2 S>D -1 SM/REM -> 0 2 }
{ 2 S>D 2 SM/REM -> 0 1 }
{ -1 S>D -1 SM/REM -> 0 1 }
{ -2 S>D -2 SM/REM -> 0 1 }
{  7 S>D  3 SM/REM -> 1 2 }
{  7 S>D -3 SM/REM -> 1 -2 }
{ -7 S>D  3 SM/REM -> -1 -2 }
{ -7 S>D -3 SM/REM -> -1 2 }
{ MAX-INT S>D 1 SM/REM -> 0 MAX-INT }
{ MIN-INT S>D 1 SM/REM -> 0 MIN-INT }
{ MAX-INT S>D MAX-INT SM/REM -> 0 1 }
{ MIN-INT S>D MIN-INT SM/REM -> 0 1 }
{ 1S 1 4 SM/REM -> 3 MAX-INT }
{ 2 MIN-INT M* 2 SM/REM -> 0 MIN-INT }
{ 2 MIN-INT M* MIN-INT SM/REM -> 0 2 }
{ 2 MAX-INT M* 2 SM/REM -> 0 MAX-INT }
{ 2 MAX-INT M* MAX-INT SM/REM -> 0 2 }
{ MIN-INT MIN-INT M* MIN-INT SM/REM -> 0 MIN-INT }
{ MIN-INT MAX-INT M* MIN-INT SM/REM -> 0 MAX-INT }
{ MIN-INT MAX-INT M* MAX-INT SM/REM -> 0 MIN-INT }
{ MAX-INT MAX-INT M* MAX-INT SM/REM -> 0 MAX-INT }

{ 0 0 1 UM/MOD -> 0 0 }
{ 1 0 1 UM/MOD -> 0 1 }
{ 1 0 2 UM/MOD -> 1 0 }
{ 3 0 2 UM/MOD -> 1 1 }
{ MAX-UINT 2 UM* 2 UM/MOD -> 0 MAX-UINT }
{ MAX-UINT 2 UM* MAX-UINT UM/MOD -> 0 2 }
{ MAX-UINT MAX-UINT UM* MAX-UINT UM/MOD -> 0 MAX-UINT }

: IFFLOORED
   [ -3 2 / -2 = INVERT ] LITERAL IF POSTPONE \ THEN ;
: IFSYM
   [ -3 2 / -1 = INVERT ] LITERAL IF POSTPONE \ THEN ;

\ THE SYSTEM MIGHT DO EITHER FLOORED OR SYMMETRIC DIVISION.
\ SINCE WE HAVE ALREADY TESTED M*, FM/MOD, AND SM/REM WE CAN USE THEM IN TEST.
IFFLOORED : T/MOD  >R S>D R> FM/MOD ;
IFFLOORED : T/     T/MOD SWAP DROP ;
IFFLOORED : TMOD   T/MOD DROP ;
IFFLOORED : T*/MOD >R M* R> FM/MOD ;
IFFLOORED : T*/    T*/MOD SWAP DROP ;
IFSYM     : T/MOD  >R S>D R> SM/REM ;
IFSYM     : T/     T/MOD SWAP DROP ;
IFSYM     : TMOD   T/MOD DROP ;
IFSYM     : T*/MOD >R M* R> SM/REM ;
IFSYM     : T*/    T*/MOD SWAP DROP ;

{ 0 1 /MOD -> 0 1 T/MOD }
{ 1 1 /MOD -> 1 1 T/MOD }
{ 2 1 /MOD -> 2 1 T/MOD }
{ -1 1 /MOD -> -1 1 T/MOD }
{ -2 1 /MOD -> -2 1 T/MOD }
{ 0 -1 /MOD -> 0 -1 T/MOD }
{ 1 -1 /MOD -> 1 -1 T/MOD }
{ 2 -1 /MOD -> 2 -1 T/MOD }
{ -1 -1 /MOD -> -1 -1 T/MOD }
{ -2 -1 /MOD -> -2 -1 T/MOD }
{ 2 2 /MOD -> 2 2 T/MOD }
{ -1 -1 /MOD -> -1 -1 T/MOD }
{ -2 -2 /MOD -> -2 -2 T/MOD }
{ 7 3 /MOD -> 7 3 T/MOD }
{ 7 -3 /MOD -> 7 -3 T/MOD }
{ -7 3 /MOD -> -7 3 T/MOD }
{ -7 -3 /MOD -> -7 -3 T/MOD }
{ MAX-INT 1 /MOD -> MAX-INT 1 T/MOD }
{ MIN-INT 1 /MOD -> MIN-INT 1 T/MOD }
{ MAX-INT MAX-INT /MOD -> MAX-INT MAX-INT T/MOD }
{ MIN-INT MIN-INT /MOD -> MIN-INT MIN-INT T/MOD }

{ 0 1 / -> 0 1 T/ }
{ 1 1 / -> 1 1 T/ }
{ 2 1 / -> 2 1 T/ }
{ -1 1 / -> -1 1 T/ }
{ -2 1 / -> -2 1 T/ }
{ 0 -1 / -> 0 -1 T/ }
{ 1 -1 / -> 1 -1 T/ }
{ 2 -1 / -> 2 -1 T/ }
{ -1 -1 / -> -1 -1 T/ }
{ -2 -1 / -> -2 -1 T/ }
{ 2 2 / -> 2 2 T/ }
{ -1 -1 / -> -1 -1 T/ }
{ -2 -2 / -> -2 -2 T/ }
{ 7 3 / -> 7 3 T/ }
{ 7 -3 / -> 7 -3 T/ }
{ -7 3 / -> -7 3 T/ }
{ -7 -3 / -> -7 -3 T/ }
{ MAX-INT 1 / -> MAX-INT 1 T/ }
{ MIN-INT 1 / -> MIN-INT 1 T/ }
{ MAX-INT MAX-INT / -> MAX-INT MAX-INT T/ }
{ MIN-INT MIN-INT / -> MIN-INT MIN-INT T/ }

{ 0 1 MOD -> 0 1 TMOD }
{ 1 1 MOD -> 1 1 TMOD }
{ 2 1 MOD -> 2 1 TMOD }
{ -1 1 MOD -> -1 1 TMOD }
{ -2 1 MOD -> -2 1 TMOD }
{ 0 -1 MOD -> 0 -1 TMOD }
{ 1 -1 MOD -> 1 -1 TMOD }
{ 2 -1 MOD -> 2 -1 TMOD }
{ -1 -1 MOD -> -1 -1 TMOD }
{ -2 -1 MOD -> -2 -1 TMOD }
{ 2 2 MOD -> 2 2 TMOD }
{ -1 -1 MOD -> -1 -1 TMOD }
{ -2 -2 MOD -> -2 -2 TMOD }
{ 7 3 MOD -> 7 3 TMOD }
{ 7 -3 MOD -> 7 -3 TMOD }
{ -7 3 MOD -> -7 3 TMOD }
{ -7 -3 MOD -> -7 -3 TMOD }
{ MAX-INT 1 MOD -> MAX-INT 1 TMOD }
{ MIN-INT 1 MOD -> MIN-INT 1 TMOD }
{ MAX-INT MAX-INT MOD -> MAX-INT MAX-INT TMOD }
{ MIN-INT MIN-INT MOD -> MIN-INT MIN-INT TMOD }

{ 0 2 1 */ -> 0 2 1 T*/ }
{ 1 2 1 */ -> 1 2 1 T*/ }
{ 2 2 1 */ -> 2 2 1 T*/ }
{ -1 2 1 */ -> -1 2 1 T*/ }
{ -2 2 1 */ -> -2 2 1 T*/ }
{ 0 2 -1 */ -> 0 2 -1 T*/ }
{ 1 2 -1 */ -> 1 2 -1 T*/ }
{ 2 2 -1 */ -> 2 2 -1 T*/ }
{ -1 2 -1 */ -> -1 2 -1 T*/ }
{ -2 2 -1 */ -> -2 2 -1 T*/ }
{ 2 2 2 */ -> 2 2 2 T*/ }
{ -1 2 -1 */ -> -1 2 -1 T*/ }
{ -2 2 -2 */ -> -2 2 -2 T*/ }
{ 7 2 3 */ -> 7 2 3 T*/ }
{ 7 2 -3 */ -> 7 2 -3 T*/ }
{ -7 2 3 */ -> -7 2 3 T*/ }
{ -7 2 -3 */ -> -7 2 -3 T*/ }
{ MAX-INT 2 MAX-INT */ -> MAX-INT 2 MAX-INT T*/ }
{ MIN-INT 2 MIN-INT */ -> MIN-INT 2 MIN-INT T*/ }

{ 0 2 1 */MOD -> 0 2 1 T*/MOD }
{ 1 2 1 */MOD -> 1 2 1 T*/MOD }
{ 2 2 1 */MOD -> 2 2 1 T*/MOD }
{ -1 2 1 */MOD -> -1 2 1 T*/MOD }
{ -2 2 1 */MOD -> -2 2 1 T*/MOD }
{ 0 2 -1 */MOD -> 0 2 -1 T*/MOD }
{ 1 2 -1 */MOD -> 1 2 -1 T*/MOD }
{ 2 2 -1 */MOD -> 2 2 -1 T*/MOD }
{ -1 2 -1 */MOD -> -1 2 -1 T*/MOD }
{ -2 2 -1 */MOD -> -2 2 -1 T*/MOD }
{ 2 2 2 */MOD -> 2 2 2 T*/MOD }
{ -1 2 -1 */MOD -> -1 2 -1 T*/MOD }
{ -2 2 -2 */MOD -> -2 2 -2 T*/MOD }
{ 7 2 3 */MOD -> 7 2 3 T*/MOD }
{ 7 2 -3 */MOD -> 7 2 -3 T*/MOD }
{ -7 2 3 */MOD -> -7 2 3 T*/MOD }
{ -7 2 -3 */MOD -> -7 2 -3 T*/MOD }
{ MAX-INT 2 MAX-INT */MOD -> MAX-INT 2 MAX-INT T*/MOD }
{ MIN-INT 2 MIN-INT */MOD -> MIN-INT 2 MIN-INT T*/MOD }

\ ------------------------------------------------------------------------
TESTING HERE , @ ! CELL+ CELLS C, C@ C! CHARS 2@ 2! ALIGN ALIGNED +! ALLOT

HERE 1 ALLOT
HERE
CONSTANT 2NDA
CONSTANT 1STA
{ 1STA 2NDA U< -> <TRUE> }		\ HERE MUST GROW WITH ALLOT
{ 1STA 1+ -> 2NDA }			\ ... BY ONE ADDRESS UNIT
( MISSING TEST: NEGATIVE ALLOT )

HERE 1 ,
HERE 2 ,
CONSTANT 2ND
CONSTANT 1ST
{ 1ST 2ND U< -> <TRUE> }			\ HERE MUST GROW WITH ALLOT
{ 1ST CELL+ -> 2ND }			\ ... BY ONE CELL
{ 1ST 1 CELLS + -> 2ND }
{ 1ST @ 2ND @ -> 1 2 }
{ 5 1ST ! -> }
{ 1ST @ 2ND @ -> 5 2 }
{ 6 2ND ! -> }
{ 1ST @ 2ND @ -> 5 6 }
{ 1ST 2@ -> 6 5 }
{ 2 1 1ST 2! -> }
{ 1ST 2@ -> 2 1 }
{ 1S 1ST !  1ST @ -> 1S }		\ CAN STORE CELL-WIDE VALUE

HERE 1 C,
HERE 2 C,
CONSTANT 2NDC
CONSTANT 1STC
{ 1STC 2NDC U< -> <TRUE> }		\ HERE MUST GROW WITH ALLOT
{ 1STC CHAR+ -> 2NDC }			\ ... BY ONE CHAR
{ 1STC 1 CHARS + -> 2NDC }
{ 1STC C@ 2NDC C@ -> 1 2 }
{ 3 1STC C! -> }
{ 1STC C@ 2NDC C@ -> 3 2 }
{ 4 2NDC C! -> }
{ 1STC C@ 2NDC C@ -> 3 4 }

ALIGN 1 ALLOT HERE ALIGN HERE 3 CELLS ALLOT
CONSTANT A-ADDR  CONSTANT UA-ADDR
{ UA-ADDR ALIGNED -> A-ADDR }
{    1 A-ADDR C!  A-ADDR C@ ->    1 }
{ 1234 A-ADDR  !  A-ADDR  @ -> 1234 }
{ 123 456 A-ADDR 2!  A-ADDR 2@ -> 123 456 }
{ 2 A-ADDR CHAR+ C!  A-ADDR CHAR+ C@ -> 2 }
{ 3 A-ADDR CELL+ C!  A-ADDR CELL+ C@ -> 3 }
{ 1234 A-ADDR CELL+ !  A-ADDR CELL+ @ -> 1234 }
{ 123 456 A-ADDR CELL+ 2!  A-ADDR CELL+ 2@ -> 123 456 }

: BITS ( X -- U )
   0 SWAP BEGIN DUP WHILE DUP MSB AND IF >R 1+ R> THEN 2* REPEAT DROP ;
( CHARACTERS >= 1 AU, <= SIZE OF CELL, >= 8 BITS )
{ 1 CHARS 1 < -> <FALSE> }
{ 1 CHARS 1 CELLS > -> <FALSE> }
( TBD: HOW TO FIND NUMBER OF BITS? )

( CELLS >= 1 AU, INTEGRAL MULTIPLE OF CHAR SIZE, >= 16 BITS )
{ 1 CELLS 1 < -> <FALSE> }
{ 1 CELLS 1 CHARS MOD -> 0 }
{ 1S BITS 10 < -> <FALSE> }

{ 0 1ST ! -> }
{ 1 1ST +! -> }
{ 1ST @ -> 1 }
{ -1 1ST +! 1ST @ -> 0 }

\ ------------------------------------------------------------------------
TESTING CHAR [CHAR] [ ] BL S"

{ BL -> 20 }
{ CHAR X -> 58 }
{ CHAR HELLO -> 48 }
{ : GC1 [CHAR] X ; -> }
{ : GC2 [CHAR] HELLO ; -> }
{ GC1 -> 58 }
{ GC2 -> 48 }
{ : GC3 [ GC1 ] LITERAL ; -> }
{ GC3 -> 58 }
{ : GC4 S" XY" ; -> }
{ GC4 SWAP DROP -> 2 }
{ GC4 DROP DUP C@ SWAP CHAR+ C@ -> 58 59 }

\ ------------------------------------------------------------------------
TESTING ' ['] FIND EXECUTE IMMEDIATE COUNT LITERAL POSTPONE STATE

{ : GT1 123 ; -> }
{ ' GT1 EXECUTE -> 123 }
{ : GT2 ['] GT1 ; IMMEDIATE -> }
{ GT2 EXECUTE -> 123 }
HERE 3 C, CHAR G C, CHAR T C, CHAR 1 C, CONSTANT GT1STRING
HERE 3 C, CHAR G C, CHAR T C, CHAR 2 C, CONSTANT GT2STRING
{ GT1STRING FIND -> ' GT1 -1 }
{ GT2STRING FIND -> ' GT2 1 }
( HOW TO SEARCH FOR NON-EXISTENT WORD? )
{ : GT3 GT2 LITERAL ; -> }
{ GT3 -> ' GT1 }
{ GT1STRING COUNT -> GT1STRING CHAR+ 3 }

{ : GT4 POSTPONE GT1 ; IMMEDIATE -> }
{ : GT5 GT4 ; -> }
{ GT5 -> 123 }
{ : GT6 345 ; IMMEDIATE -> }
{ : GT7 POSTPONE GT6 ; -> }
{ GT7 -> 345 }

{ : GT8 STATE @ ; IMMEDIATE -> }
{ GT8 -> 0 }
{ : GT9 GT8 LITERAL ; -> }
{ GT9 0= -> <FALSE> }

\ ------------------------------------------------------------------------
TESTING IF ELSE THEN BEGIN WHILE REPEAT UNTIL RECURSE

{ : GI1 IF 123 THEN ; -> }
{ : GI2 IF 123 ELSE 234 THEN ; -> }
{ 0 GI1 -> }
{ 1 GI1 -> 123 }
{ -1 GI1 -> 123 }
{ 0 GI2 -> 234 }
{ 1 GI2 -> 123 }
{ -1 GI1 -> 123 }

{ : GI3 BEGIN DUP 5 < WHILE DUP 1+ REPEAT ; -> }
{ 0 GI3 -> 0 1 2 3 4 5 }
{ 4 GI3 -> 4 5 }
{ 5 GI3 -> 5 }
{ 6 GI3 -> 6 }

{ : GI4 BEGIN DUP 1+ DUP 5 > UNTIL ; -> }
{ 3 GI4 -> 3 4 5 6 }
{ 5 GI4 -> 5 6 }
{ 6 GI4 -> 6 7 }

{ : GI5 BEGIN DUP 2 > WHILE DUP 5 < WHILE DUP 1+ REPEAT 123 ELSE 345 THEN ; -> }
{ 1 GI5 -> 1 345 }
{ 2 GI5 -> 2 345 }
{ 3 GI5 -> 3 4 5 123 }
{ 4 GI5 -> 4 5 123 }
{ 5 GI5 -> 5 123 }

{ : GI6 ( N -- 0,1,..N ) DUP IF DUP >R 1- RECURSE R> THEN ; -> }
{ 0 GI6 -> 0 }
{ 1 GI6 -> 0 1 }
{ 2 GI6 -> 0 1 2 }
{ 3 GI6 -> 0 1 2 3 }
{ 4 GI6 -> 0 1 2 3 4 }

\ ------------------------------------------------------------------------
TESTING DO LOOP +LOOP I J UNLOOP LEAVE EXIT

{ : GD1 DO I LOOP ; -> }
{ 4 1 GD1 -> 1 2 3 }
{ 2 -1 GD1 -> -1 0 1 }
{ MID-UINT+1 MID-UINT GD1 -> MID-UINT }

{ : GD2 DO I -1 +LOOP ; -> }
{ 1 4 GD2 -> 4 3 2 1 }
{ -1 2 GD2 -> 2 1 0 -1 }
{ MID-UINT MID-UINT+1 GD2 -> MID-UINT+1 MID-UINT }

{ : GD3 DO 1 0 DO J LOOP LOOP ; -> }
{ 4 1 GD3 -> 1 2 3 }
{ 2 -1 GD3 -> -1 0 1 }
{ MID-UINT+1 MID-UINT GD3 -> MID-UINT }

{ : GD4 DO 1 0 DO J LOOP -1 +LOOP ; -> }
{ 1 4 GD4 -> 4 3 2 1 }
{ -1 2 GD4 -> 2 1 0 -1 }
{ MID-UINT MID-UINT+1 GD4 -> MID-UINT+1 MID-UINT }

{ : GD5 123 SWAP 0 DO I 4 > IF DROP 234 LEAVE THEN LOOP ; -> }
{ 1 GD5 -> 123 }
{ 5 GD5 -> 123 }
{ 6 GD5 -> 234 }

{ : GD6  ( PAT: {0 0},{0 0}{1 0}{1 1},{0 0}{1 0}{1 1}{2 0}{2 1}{2 2} )
   0 SWAP 0 DO
      I 1+ 0 DO I J + 3 = IF I UNLOOP I UNLOOP EXIT THEN 1+ LOOP
    LOOP ; -> }
{ 1 GD6 -> 1 }
{ 2 GD6 -> 3 }
{ 3 GD6 -> 4 1 2 }

\ ------------------------------------------------------------------------
TESTING DEFINING WORDS: : ; CONSTANT VARIABLE CREATE DOES> >BODY

{ 123 CONSTANT X123 -> }
{ X123 -> 123 }
{ : EQU CONSTANT ; -> }
{ X123 EQU Y123 -> }
{ Y123 -> 123 }

{ VARIABLE V1 -> }
{ 123 V1 ! -> }
{ V1 @ -> 123 }

{ : NOP : POSTPONE ; ; -> }
{ NOP NOP1 NOP NOP2 -> }
{ NOP1 -> }
{ NOP2 -> }

{ : DOES1 DOES> @ 1 + ; -> }
{ : DOES2 DOES> @ 2 + ; -> }
{ CREATE CR1 -> }
{ CR1 -> HERE }
{ ' CR1 >BODY -> HERE }
{ 1 , -> }
{ CR1 @ -> 1 }
{ DOES1 -> }
{ CR1 -> 2 }
{ DOES2 -> }
{ CR1 -> 3 }

{ : WEIRD: CREATE DOES> 1 + DOES> 2 + ; -> }
{ WEIRD: W1 -> }
{ ' W1 >BODY -> HERE }
{ W1 -> HERE 1 + }
{ W1 -> HERE 2 + }

\ ------------------------------------------------------------------------
TESTING EVALUATE

: GE1 S" 123" ; IMMEDIATE
: GE2 S" 123 1+" ; IMMEDIATE
: GE3 S" : GE4 345 ;" ;
: GE5 EVALUATE ; IMMEDIATE

{ GE1 EVALUATE -> 123 }			( TEST EVALUATE IN INTERP. STATE )
{ GE2 EVALUATE -> 124 }
{ GE3 EVALUATE -> }
{ GE4 -> 345 }

{ : GE6 GE1 GE5 ; -> }			( TEST EVALUATE IN COMPILE STATE )
{ GE6 -> 123 }
{ : GE7 GE2 GE5 ; -> }
{ GE7 -> 124 }

\ ------------------------------------------------------------------------
TESTING SOURCE >IN WORD

: GS1 S" SOURCE" 2DUP EVALUATE
       >R SWAP >R = R> R> = ;
{ GS1 -> <TRUE> <TRUE> }

VARIABLE SCANS
: RESCAN?  -1 SCANS +! SCANS @ IF 0 >IN ! THEN ;

{ 2 SCANS !
345 RESCAN?
-> 345 345 }

: GS2  5 SCANS ! S" 123 RESCAN?" EVALUATE ;
{ GS2 -> 123 123 123 123 123 }

: GS3 WORD COUNT SWAP C@ ;
{ BL GS3 HELLO -> 5 CHAR H }
{ CHAR " GS3 GOODBYE" -> 7 CHAR G }
{ BL GS3
DROP -> 0 }				\ BLANK LINE RETURN ZERO-LENGTH STRING

: GS4 SOURCE >IN ! DROP ;
{ GS4 123 456
-> }

\ ------------------------------------------------------------------------
TESTING <# # #S #> HOLD SIGN BASE >NUMBER HEX DECIMAL

: S=  \ ( ADDR1 C1 ADDR2 C2 -- T/F ) COMPARE TWO STRINGS.
   >R SWAP R@ = IF			\ MAKE SURE STRINGS HAVE SAME LENGTH
      R> ?DUP IF			\ IF NON-EMPTY STRINGS
	 0 DO
	    OVER C@ OVER C@ - IF 2DROP <FALSE> UNLOOP EXIT THEN
	    SWAP CHAR+ SWAP CHAR+
         LOOP
      THEN
      2DROP <TRUE>			\ IF WE GET HERE, STRINGS MATCH
   ELSE
      R> DROP 2DROP <FALSE>		\ LENGTHS MISMATCH
   THEN ;

: GP1  <# 41 HOLD 42 HOLD 0 0 #> S" BA" S= ;
{ GP1 -> <TRUE> }

: GP2  <# -1 SIGN 0 SIGN -1 SIGN 0 0 #> S" --" S= ;
{ GP2 -> <TRUE> }

: GP3  <# 1 0 # # #> S" 01" S= ;
{ GP3 -> <TRUE> }

: GP4  <# 1 0 #S #> S" 1" S= ;
{ GP4 -> <TRUE> }

24 CONSTANT MAX-BASE			\ BASE 2 .. 36
: COUNT-BITS
   0 0 INVERT BEGIN DUP WHILE >R 1+ R> 2* REPEAT DROP ;
COUNT-BITS 2* CONSTANT #BITS-UD		\ NUMBER OF BITS IN UD

: GP5
   BASE @ <TRUE>
   MAX-BASE 1+ 2 DO			\ FOR EACH POSSIBLE BASE
      I BASE !				\ TBD: ASSUMES BASE WORKS
      I 0 <# #S #> S" 10" S= AND
   LOOP
   SWAP BASE ! ;
{ GP5 -> <TRUE> }

: GP6
   BASE @ >R  2 BASE !
   MAX-UINT MAX-UINT <# #S #>		\ MAXIMUM UD TO BINARY
   R> BASE !				\ S: C-ADDR U
   DUP #BITS-UD = SWAP
   0 DO					\ S: C-ADDR FLAG
      OVER C@ [CHAR] 1 = AND		\ ALL ONES
      >R CHAR+ R>
   LOOP SWAP DROP ;
{ GP6 -> <TRUE> }

: GP7
   BASE @ >R    MAX-BASE BASE !
   <TRUE>
   A 0 DO
      I 0 <# #S #>
      1 = SWAP C@ I 30 + = AND AND
   LOOP
   MAX-BASE A DO
      I 0 <# #S #>
      1 = SWAP C@ 41 I A - + = AND AND
   LOOP
   R> BASE ! ;

{ GP7 -> <TRUE> }

\ >NUMBER TESTS
CREATE GN-BUF 0 C,
: GN-STRING	GN-BUF 1 ;
: GN-CONSUMED	GN-BUF CHAR+ 0 ;
: GN'		[CHAR] ' WORD CHAR+ C@ GN-BUF C!  GN-STRING ;

{ 0 0 GN' 0' >NUMBER -> 0 0 GN-CONSUMED }
{ 0 0 GN' 1' >NUMBER -> 1 0 GN-CONSUMED }
{ 1 0 GN' 1' >NUMBER -> BASE @ 1+ 0 GN-CONSUMED }
{ 0 0 GN' -' >NUMBER -> 0 0 GN-STRING }	\ SHOULD FAIL TO CONVERT THESE
{ 0 0 GN' +' >NUMBER -> 0 0 GN-STRING }
{ 0 0 GN' .' >NUMBER -> 0 0 GN-STRING }

: >NUMBER-BASED
   BASE @ >R BASE ! >NUMBER R> BASE ! ;

{ 0 0 GN' 2' 10 >NUMBER-BASED -> 2 0 GN-CONSUMED }
{ 0 0 GN' 2'  2 >NUMBER-BASED -> 0 0 GN-STRING }
{ 0 0 GN' F' 10 >NUMBER-BASED -> F 0 GN-CONSUMED }
{ 0 0 GN' G' 10 >NUMBER-BASED -> 0 0 GN-STRING }
{ 0 0 GN' G' MAX-BASE >NUMBER-BASED -> 10 0 GN-CONSUMED }
{ 0 0 GN' Z' MAX-BASE >NUMBER-BASED -> 23 0 GN-CONSUMED }

: GN1	\ ( UD BASE -- UD' LEN ) UD SHOULD EQUAL UD' AND LEN SHOULD BE ZERO.
   BASE @ >R BASE !
   <# #S #>
   0 0 2SWAP >NUMBER SWAP DROP		\ RETURN LENGTH ONLY
   R> BASE ! ;
{ 0 0 2 GN1 -> 0 0 0 }
{ MAX-UINT 0 2 GN1 -> MAX-UINT 0 0 }
{ MAX-UINT DUP 2 GN1 -> MAX-UINT DUP 0 }
{ 0 0 MAX-BASE GN1 -> 0 0 0 }
{ MAX-UINT 0 MAX-BASE GN1 -> MAX-UINT 0 0 }
{ MAX-UINT DUP MAX-BASE GN1 -> MAX-UINT DUP 0 }

: GN2	\ ( -- 16 10 )
   BASE @ >R  HEX BASE @  DECIMAL BASE @  R> BASE ! ;
{ GN2 -> 10 A }

\ ------------------------------------------------------------------------
TESTING FILL MOVE

CREATE FBUF 00 C, 00 C, 00 C,
CREATE SBUF 12 C, 34 C, 56 C,
: SEEBUF FBUF C@  FBUF CHAR+ C@  FBUF CHAR+ CHAR+ C@ ;

{ FBUF 0 20 FILL -> }
{ SEEBUF -> 00 00 00 }

{ FBUF 1 20 FILL -> }
{ SEEBUF -> 20 00 00 }

{ FBUF 3 20 FILL -> }
{ SEEBUF -> 20 20 20 }

{ FBUF FBUF 3 CHARS MOVE -> }		\ BIZARRE SPECIAL CASE
{ SEEBUF -> 20 20 20 }

{ SBUF FBUF 0 CHARS MOVE -> }
{ SEEBUF -> 20 20 20 }

{ SBUF FBUF 1 CHARS MOVE -> }
{ SEEBUF -> 12 20 20 }

{ SBUF FBUF 3 CHARS MOVE -> }
{ SEEBUF -> 12 34 56 }

{ FBUF FBUF CHAR+ 2 CHARS MOVE -> }
{ SEEBUF -> 12 12 34 }

{ FBUF CHAR+ FBUF 2 CHARS MOVE -> }
{ SEEBUF -> 12 34 34 }

\ ------------------------------------------------------------------------
TESTING OUTPUT: . ." CR EMIT SPACE SPACES TYPE U.

: OUTPUT-TEST
   ." YOU SHOULD SEE THE STANDARD GRAPHIC CHARACTERS:" CR
   41 BL DO I EMIT LOOP CR
   61 41 DO I EMIT LOOP CR
   7F 61 DO I EMIT LOOP CR
   ." YOU SHOULD SEE 0-9 SEPARATED BY A SPACE:" CR
   9 1+ 0 DO I . LOOP CR
   ." YOU SHOULD SEE 0-9 (WITH NO SPACES):" CR
   [CHAR] 9 1+ [CHAR] 0 DO I 0 SPACES EMIT LOOP CR
   ." YOU SHOULD SEE A-G SEPARATED BY A SPACE:" CR
   [CHAR] G 1+ [CHAR] A DO I EMIT SPACE LOOP CR
   ." YOU SHOULD SEE 0-5 SEPARATED BY TWO SPACES:" CR
   5 1+ 0 DO I [CHAR] 0 + EMIT 2 SPACES LOOP CR
   ." YOU SHOULD SEE TWO SEPARATE LINES:" CR
   S" LINE 1" TYPE CR S" LINE 2" TYPE CR
   ." YOU SHOULD SEE THE NUMBER RANGES OF SIGNED AND UNSIGNED NUMBERS:" CR
   ."   SIGNED: " MIN-INT . MAX-INT . CR
   ." UNSIGNED: " 0 U. MAX-UINT U. CR
;

{ OUTPUT-TEST -> }

\ ------------------------------------------------------------------------
TESTING INPUT: ACCEPT

CREATE ABUF 80 CHARS ALLOT

: ACCEPT-TEST
   CR ." PLEASE TYPE UP TO 80 CHARACTERS:" CR
   ABUF 80 ACCEPT
   CR ." RECEIVED: " [CHAR] " EMIT
   ABUF SWAP TYPE [CHAR] " EMIT CR
;

{ ACCEPT-TEST -> }

\ ------------------------------------------------------------------------
TESTING DICTIONARY SEARCH RULES

{ : GDX   123 ; : GDX   GDX 234 ; -> }

{ GDX -> 123 234 }


\ test suite finished. leaving engine.

bye
