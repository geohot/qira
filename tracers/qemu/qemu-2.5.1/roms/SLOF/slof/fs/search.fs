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
\
\ Copyright 2002,2003,2004  Segher Boessenkool  <segher@kernel.crashing.org>
\


\ stuff we should already have:

: linked ( var -- )  here over @ , swap ! ;

HEX

\ \ \
\ \ \	Wordlists
\ \ \

VARIABLE wordlists  forth-wordlist wordlists !

\ create a new wordlist
: wordlist ( -- wid )  here wordlists linked 0 , ;


\ \ \
\ \ \	Search order
\ \ \

10 CONSTANT max-in-search-order	\ should define elsewhere
\ CREATE search-order max-in-search-order cells allot	\ stack of wids	\ is in engine now
\ search-order VALUE context	\ top of stack	\ is in engine now

: also ( -- )  clean-hash  context dup cell+ dup to context  >r @ r> ! ;
: previous ( -- )  clean-hash  context cell- to context ;
: only ( -- )  clean-hash  search-order to context  ( minimal-wordlist search-order ! ) ;
: seal ( -- )  clean-hash  context @  search-order dup to context  ! ;

: get-order ( -- wid_n .. wid_1 n )
	context >r search-order BEGIN dup r@ u<= WHILE
	dup @ swap cell+ REPEAT r> drop
	search-order - cell / ;
: set-order ( wid_n .. wid_1 n -- )	\ XXX: special cases for 0, -1
	clean-hash  1- cells search-order + dup to context
	BEGIN dup search-order u>= WHILE
	dup >r ! r> cell- REPEAT drop ;


\ \ \
\ \ \	Compilation wordlist
\ \ \

: get-current ( -- wid )  current ;
: set-current ( wid -- )  to current ;

: definitions ( -- )  context @ set-current ;


\ \ \
\ \ \	Vocabularies
\ \ \

: VOCABULARY ( C: "name" -- ) ( -- )  CREATE wordlist drop  DOES> clean-hash  context ! ;
\ : VOCABULARY ( C: "name" -- ) ( -- )  wordlist CREATE ,  DOES> @ context ! ;
\ XXX we'd like to swap forth and forth-wordlist around (for .voc 's sake)
: FORTH ( -- )  clean-hash  forth-wordlist context ! ;

: .voc ( wid -- ) \ display name for wid \ needs work ( body> or something like that )
	dup cell- @ ['] vocabulary ['] forth within IF
	2 cells - >name name>string type ELSE u. THEN  space ;
: vocs ( -- ) \ display all wordlist names
	cr wordlists BEGIN @ dup WHILE dup .voc REPEAT drop ;
: order ( -- )
	cr ." context:  " get-order 0 ?DO .voc LOOP
	cr ." current:  " get-current .voc ;




\ some handy helper
: voc-find ( wid -- 0 | link )
   clean-hash  cell+ @ (find)  clean-hash ;
