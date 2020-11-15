\ tag: self-test
\ 
\ this code implements IEEE 1275-1994 ch. 7.4.8
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ 
\ 7.4.8    Self-test
\ 

: $test ( devname-addr devname-len -- )
  2dup ." Testing device " type ." : "
  find-dev if
    s" self-test" rot find-method if
      execute
    else 
      ." no self-test method."
    then
  else
    ." no such device."
  then
  cr
;

: test    ( "device-specifier<cr>"-- )
  linefeed parse cr $test
  ;
  
: test-sub-devs
  >dn.child @
  begin dup while
    dup get-package-path $test
    dup recurse
    >dn.peer @
  repeat
  drop
;
  
: test-all    ( "{device-specifier}<cr>" -- )
  active-package
  cr " /" find-device
  linefeed parse find-device
  ?active-package test-sub-devs
  active-package!
  ;
