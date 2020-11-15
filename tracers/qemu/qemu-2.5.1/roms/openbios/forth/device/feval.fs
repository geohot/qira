\ tag: FCode evaluator
\ 
\ this code implements an fcode evaluator 
\ as described in IEEE 1275-1994
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

defer init-fcode-table

: alloc-fcode-table 
  4096 cells alloc-mem to fcode-table
  ?fcode-verbose if
    ." fcode-table at 0x" fcode-table . cr
  then
  init-fcode-table
  ;
 
: free-fcode-table
  fcode-table 4096 cells free-mem
  0 to fcode-table
  ;

: (debug-feval) ( fcode# -- fcode# )
  \ Address
  fcode-stream 1 - . ." : "

  \ Indicate if word is compiled
  state @ 0<> if
    ." (compile) "
  then
  dup fcode>xt cell - lfa2name type
  dup ."  [ 0x" . ." ]" cr
  ;

: (feval) ( -- ?? )
  begin
    fcode#
    ?fcode-verbose if
      (debug-feval)
    then
    fcode>xt
    dup flags? 0<> state @ 0= or if
      execute
    else
      ,
    then
  fcode-end @ until

  \ If we've executed incorrect FCode we may have reached the end of the FCode
  \ program but still be in compile mode. Make sure that if this has happened
  \ then we switch back to immediate mode to prevent internal OpenBIOS errors.
  tmp-comp-depth @ -1 <> if
    -1 tmp-comp-depth !
    tmp-comp-buf @ @ here!
    0 state !
  then
;

: byte-load ( addr xt -- )
  ?fcode-verbose if
    cr ." byte-load: evaluating fcode at 0x" over . cr
  then

  \ save state
  >r >r fcode-push-state r> r>

  \ set fcode-c@ defer
  dup 1 = if drop ['] c@ then      \ FIXME: uses c@ rather than rb@ for now...
  to fcode-c@
  dup to fcode-stream-start
  to fcode-stream
  1 to fcode-spread
  false to ?fcode-offset16 
  alloc-fcode-table
  false fcode-end !
  
  \ protect against stack overflow/underflow
  0 0 0 0 0 0 depth >r
  
  ['] (feval) catch if
    cr ." byte-load: exception caught!" cr
  then

  s" fcode-debug?" evaluate if
    depth r@ <> if
      cr ." byte-load: warning stack overflow, diff " depth r@ - . cr
    then
  then

  r> depth! 3drop 3drop

  free-fcode-table

  \ restore state
  fcode-pop-state
;
