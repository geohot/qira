\ tag: forth interpreter
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 


\ 
\ 7.3.4.6 Display pause
\ 

0 value interactive?
0 value terminate?

: exit?
  interactive? 0= if
    false exit
  then
  false \ FIXME we should check whether to interrupt output
        \ and ask the user how to proceed.
  ;


\ 
\ 7.3.9.1 Defining words
\ 

: forget 
  s" This word is obsolescent." type cr
  ['] ' execute
  cell - dup 
  @ dup 
  last ! latest !
  here!
  ;
 
\ 
\ 7.3.9.2.4 Miscellaneous dictionary
\ 

\ interpreter. This word checks whether the interpreted word
\ is a word in dictionary or a number. It honours compile mode 
\ and immediate/compile-only words.

: interpret 
  0 >in !
  begin
    parse-word dup 0> \ was there a word at all?
  while
    $find 
    if
      dup flags? 0<> state @ 0= or if
        execute
      else
        ,             \ compile mode && !immediate
      then
    else              \ word is not known. maybe it's a number
      2dup $number
      if
        span @ >in !  \ if we encountered an error, don't continue parsing
        type 3a emit
	-13 throw
      else
        -rot 2drop 1 handle-lit
      then
    then
    depth 200 >=  if -3 throw then 
    depth 0<      if -4 throw then
    rdepth 200 >= if -5 throw then 
    rdepth 0<     if -6 throw then
  repeat
  2drop
  ;

: refill ( -- )
	ib #ib @ expect 0 >in ! ;

: print-status  ( exception -- )
  space
  ?dup if
    dup sys-debug \ system debug hook
    case 
       -1 of s" Aborted." type endof
       -2 of s" Aborted." type endof
       -3 of s" Stack Overflow." type 0 depth! endof
       -4 of s" Stack Underflow." type 0 depth! endof
       -5 of s" Return Stack Overflow." type endof
       -6 of s" Return Stack Underflow." type endof
      -13 of s" undefined word." type endof
      -15 of s" out of memory." type endof
      -21 of s" undefined method." type endof
      -22 of s" no such device." type endof
      dup s" Exception #" type . 
      0 state !
    endcase
  else
    state @ 0= if
      s" ok"
    else 
      s" compiled"
    then
    type
  then
  cr
  ;

defer status
['] noop ['] status (to)

: print-prompt
  status 
  depth . 3e emit space
  ;
  
defer outer-interpreter
:noname
  cr
  begin
    print-prompt
    source 0 fill           \ clean input buffer
    refill 

    ['] interpret catch print-status
    terminate?
  until
; ['] outer-interpreter (to)

\ 
\ 7.3.8.5 Other control flow commands
\ 

: save-source  ( -- )
  r>               \ fetch our caller
  ib >r #ib @ >r   \ save current input buffer
  source-id >r     \ and all variables 
  span @ >r        \ associated with it.
  >in @ >r
  >r               \ move back our caller
  ;

: restore-source ( -- )
  r> 
  r> >in ! 
  r> span ! 
  r> ['] source-id (to) 
  r> #ib ! 
  r> ['] ib (to) 
  >r
  ;

: (evaluate) ( str len -- ??? )
  save-source
  -1 ['] source-id (to)
  dup
  #ib ! span !
  ['] ib (to)
  interpret
  restore-source
  ; 

: evaluate ( str len -- ?? )
  2dup + -rot
  over + over do 
    i c@ 0a = if 
      i over - 
      (evaluate)
      i 1+ 
    then 
  loop 
  swap over - (evaluate)
  ;
  
: eval evaluate ;
