\ tag: Utility functions
\ 
\ Utility functions
\ 
\ Copyright (C) 2003, 2004 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ -------------------------------------------------------------------------
\ package utils
\ -------------------------------------------------------------------------

( method-str method-len package-str package-len -- xt|0 )
: $find-package-method
  find-package 0= if 2drop false exit then
  find-method 0= if 0 then
;

\ like $call-parent but takes an xt
: call-parent ( ... xt -- ??? )
  my-parent call-package
;

: [active-package],
	['] (lit) , active-package ,
; immediate

\ -------------------------------------------------------------------------
\ word creation
\ -------------------------------------------------------------------------

: ?mmissing ( name len -- 1 name len | 0 )
  2dup active-package find-method
  if 3drop false else true then
;

\ install trivial open and close functions
: is-open ( -- )
  " open" ?mmissing if ['] true -rot is-xt-func then
  " close" ?mmissing if 0 -rot is-xt-func then
;

\ is-relay installs a relay function (a function that calls
\ a function with the same name but belonging to a different node).
\ The execution behaviour of xt should be ( -- ptr-to-ihandle ).
\ 
: is-relay ( xt ph name-str name-len -- )
  rot >r 2dup r> find-method 0= if
    \ function missing (not necessarily an error)
    3drop exit
  then

  -rot is-func-begin
  ( xt method-xt )
  ['] (lit) , ,                 \ ['] method
  , ['] @ ,                     \ xt @
  ['] call-package ,            \ call-package
  is-func-end
;

\ -------------------------------------------------------------------------
\ install deblocker bindings
\ -------------------------------------------------------------------------

: (open-deblocker) ( varaddr -- )
  " deblocker" find-package if
    0 0 rot open-package
  else 0 then
  swap !
;
  
: is-deblocker ( -- )
  " deblocker" find-package 0= if exit then >r
  " deblocker" is-ivariable

  \ create open-deblocker
  " open-deblocker" is-func-begin
  dup , ['] (open-deblocker) ,
  is-func-end

  \ create close-deblocker
  " close-deblocker" is-func-begin
  dup , ['] @ , ['] close-package ,
  is-func-end
  
  ( save-ph deblk-xt R: deblocker-ph  )
  r>
  2dup " read" is-relay
  2dup " seek" is-relay
  2dup " write" is-relay
  2dup " tell" is-relay
  2drop
;
