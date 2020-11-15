\ tag: vocabulary implementation for openbios
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ 
\ this is an implementation of DPANS94 wordlists (SEARCH EXT)
\ 


16 constant #vocs
create vocabularies #vocs cells allot \ word lists
['] vocabularies to context

: search-wordlist ( c-addr u wid -- 0 | xt 1 | xt -1 )
  \ Find the definition identified by the string c-addr u in the word 
  \ list identified by wid. If the definition is not found, return zero. 
  \ If the definition is found, return its execution token xt and
  \ one (1) if the definition is immediate, minus-one (-1) otherwise.
  find-wordlist
  if
    true over immediate? if
      negate
    then
  else
    2drop false
  then
  ;

: wordlist ( -- wid )
  \ Creates a new empty word list, returning its word list identifier 
  \ wid. The new word list may be returned from a pool of preallocated 
  \ word lists or may be dynamically allocated in data space. A system 
  \ shall allow the creation of at least 8 new word lists in addition 
  \ to any provided as part of the system.
  here 0 ,
  ;

: get-order ( -- wid1 .. widn n )
  #order @ 0 ?do
    #order @ i - 1- cells context + @
  loop
  #order @
  ;

: set-order ( wid1 .. widn n -- )
  dup -1 = if
    drop forth-last 1 \ push system default word list and number of lists
  then
  dup #order !
  0 ?do 
    i cells context + ! 
  loop
  ;

: order ( -- )
  \ display word lists in the search order in their search order sequence
  \ from the first searched to last searched. Also display word list into
  \ which new definitions will be placed. 
  cr
  get-order 0 ?do
    ." wordlist " i (.) type 2e emit space u. cr
  loop
  cr ." definitions: " current @ u. cr
  ;
 
  
: previous ( -- )
  \ Transform the search order consisting of widn, ... wid2, wid1 (where 
  \ wid1 is searched first) into widn, ... wid2. An ambiguous condition 
  \ exists if the search order was empty before PREVIOUS was executed.
  get-order nip 1- set-order 
  ;
 
  
: do-vocabulary ( -- )	\ implementation factor
  does> 
    @ >r		(  ) ( R: widnew )
    get-order swap drop	( wid1 ... widn-1 n )
    r> swap set-order
  ;

: discard ( x1 .. xu u - ) \ implementation factor
  0 ?do 
    drop 
  loop
  ;

: vocabulary ( >name -- )
  wordlist create , do-vocabulary
  ;

: also  ( -- )
  get-order over swap 1+ set-order
  ;

: only  ( -- ) 
  -1 set-order also
  ;
 
only

\ create forth forth-wordlist , do-vocabulary
create forth get-order over , discard do-vocabulary

: findw  ( c-addr -- c-addr 0 | w 1 | w -1 )
  0			( c-addr 0 )
  #order @ 0 ?do
    over count 		( c-addr 0 c-addr' u       )
    i cells context + @ ( c-addr 0 c-addr' u wid   )
    search-wordlist	( c-addr 0; 0 | w 1 | w -1 )
    ?dup if		( c-addr 0; w 1 | w -1     )
      2swap 2drop leave ( w 1 | w -1 )
    then                ( c-addr 0   )
  loop			( c-addr 0 | w 1 | w -1    )
  ;

: get-current ( -- wid )
  current @
  ;

: set-current ( wid -- )
  current !
  ;

: definitions ( -- )
  \ Make the compilation word list the same as the first word list in 
  \ the search order. Specifies that the names of subsequent definitions 
  \ will be placed in the compilation word list.
  \ Subsequent changes in the search order will not affect the 
  \ compilation word list.
  context @ set-current
  ;
  
: forth-wordlist ( -- wid )
  forth-last
  ;

: #words ( -- )
  0 last
  begin 
    @ ?dup 
  while
    swap 1+ swap
  repeat
  
  cr
  ;
 
true to vocabularies?
