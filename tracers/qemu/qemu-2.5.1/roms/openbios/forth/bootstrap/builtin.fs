\ tag: initialize builtin functionality
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

 

: init-builtin-terminal  ( -- )

  \ define key, key? and emit
  ['] (key) ['] key (to)
  ['] (key?) ['] key? (to)
  ['] (emit) ['] emit (to)

  \ 2 bytes band guard on each side
  100 #ib !
  #ib @ dup             ( -- ibs ibs )
  cell+ alloc-mem       ( -- ibs addr )
  dup -rot              ( -- addr ibs addr )

  /w + ['] ib (to)      \ assign input buffer
  0 fill                \ erase tib
  0 ['] source-id (to)  \ builtin terminal has id 0

  ;
