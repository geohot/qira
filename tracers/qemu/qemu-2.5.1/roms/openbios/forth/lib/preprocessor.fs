\ tag: Forth preprocessor
\ 
\ Forth preprocessor
\ 
\ Copyright (C) 2003, 2004 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

0 value prep-wid
0 value prep-dict
0 value prep-here

: ([IF])
  begin
    begin parse-word dup 0= while
      2drop refill
    repeat

    2dup " [IF]" strcmp 0= if 1 throw then
    2dup " [IFDEF]" strcmp 0= if 1 throw then
    2dup " [ELSE]" strcmp 0= if 2 throw then
    2dup " [THEN]" strcmp 0= if 3 throw then
    " \\" strcmp 0= if linefeed parse 2drop then
  again
;

: [IF] ( flag -- )
  if exit then
  1 begin
    ['] ([IF]) catch case
      \ EOF (FIXME: this does not work)
      \ -1 of ." Missing [THEN]" abort exit endof
      \ [IF]
      1 of 1+ endof
      \ [ELSE]
      2 of dup 1 = if 1- then endof
      \ [THEN]
      3 of 1- endof
    endcase
  dup 0 <=
  until drop
; immediate

: [ELSE] 0 [ ['] [IF] , ] ; immediate
: [THEN] ; immediate

:noname
  0 to prep-wid
  0 to prep-dict
; initializer

: [IFDEF] ( <word> -- )
  prep-wid if
    parse-word prep-wid search-wordlist dup if nip then
  else 0 then
  [ ['] [IF] , ]
; immediate

: [DEFINE] ( <word> -- )
  parse-word here get-current >r >r
  prep-dict 0= if
    2000 alloc-mem here!
    here to prep-dict
    wordlist to prep-wid
    here to prep-here
  then
  prep-wid set-current prep-here here!
  $create
  here to prep-here
  r> r> set-current here!
; immediate

: [0] 0 ; immediate
: [1] 1 ; immediate
