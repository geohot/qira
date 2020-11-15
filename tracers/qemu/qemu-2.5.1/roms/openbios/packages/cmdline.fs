\ tag: Utility functions
\ 
\ deblocker / filesystem support
\ 
\ Copyright (C) 2003, 2004 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ -------------------------------------------------------------
\ command line editor (/packages/cmdline)
\ -------------------------------------------------------------

[IFDEF] CONFIG_CMDLINE

dev /packages
new-device
  " cmdline" device-name

  :noname
    " " [active-package], open-package
    ?dup if
      " cmdline" rot $call-method
    else
      ." cmdline is missing!" cr
    then
    \ cmdline must close itself upon return
  ;

  :noname
    [ ['] (lit) , swap , ] to outer-interpreter
  ; SYSTEM-initializer

  external
  : prepare 0 to my-self ;

finish-device

[THEN]
device-end
