\ tag: misc useful functions
\ 
\ C bindings
\ 
\ Copyright (C) 2003, 2004 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ return xt of the word just defined
: last-xt ( -- xt )
  latest @ na1+
;

\ -------------------------------------------------------------------------
\ word creation
\ -------------------------------------------------------------------------

: $is-ibuf ( size name name-len -- xt )
  instance $buffer: drop
  last-xt
;

: is-ibuf ( size -- xt )
  0 0 $is-ibuf
;

: is-ivariable ( size name len -- xt )
  4 -rot instance $buffer: drop
  last-xt
;

: is-xt-func ( xt|0 wordstr len )
  header 1 ,
  ?dup if , then
  ['] (semis) , reveal
;

: is-2xt-func ( xt1 xt2 wordstr len )
  header 1 ,
  swap , ,
  ['] (semis) , reveal
;

: is-func-begin ( wordstr len )
  header 1 ,
;

: is-func-end ( wordstr len )
  ['] (semis) , reveal
;
