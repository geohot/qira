\ tag: misc useful functions
\ 
\ Misc useful functions
\ 
\ Copyright (C) 2003 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ -------------------------------------------------------------------------
\ statically allocated lists
\ -------------------------------------------------------------------------
\ list-head should be a variable

: list-add ( listhead -- )
  here 0 , swap                  \ next, [data...]
  ( here listhead )
  begin dup @ while @ repeat !
;

: list-get ( listptr -- nextlistptr dictptr true | false )
  @ dup if
    dup na1+ true
  then
;
