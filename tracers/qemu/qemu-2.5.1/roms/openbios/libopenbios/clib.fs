\ tag: C helpers
\ 
\ Misc C helpers
\ 
\ Copyright (C) 2003, 2004 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ should perhaps be moved somewhere else
: set-property ( buf len propname propname-len phandle -- )
	>r 2swap encode-bytes 2swap r> encode-property
;

\ install C function
: is-cfunc ( funcaddr word word-len -- )
  $create , does> @ call
;

\ install a nameless C function
: is-noname-cfunc ( funcaddr -- xt )
  0 0 is-cfunc last-xt
;

\ is-xt-cfunc installs a function which does the following:
\   - xt is executes
\   - funcarg is pushed
\   - funcaddr is called

: is-xt-cfunc ( xt|0 funcarg funcaddr word word-len -- )
	is-func-begin
  rot ?dup if , then
  swap ['] (lit) , , ['] (lit) , , ['] call ,
	is-func-end
;
