\ tag: stdin/stdout handling
\ 
\ Copyright (C) 2003 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ 7.4.5    I/O control

variable stdout
variable stdin

: input    ( dev-str dev-len -- )
  2dup find-dev 0= if
    ." Input device " type ."  not found." cr exit
  then

  " read" rot find-method 0= if
    type ."  has no read method." cr exit
  then
  drop
  
  \ open stdin device
  2dup open-dev ?dup 0= if
    ." Opening " type ."  failed." cr exit
  then
  -rot 2drop

  \ call install-abort if present
  dup " install-abort" rot ['] $call-method catch if 3drop then

  \ close old stdin
  stdin @ ?dup if
    dup " remove-abort" rot ['] $call-method catch if 3drop then
    close-dev
  then
  stdin !

  \ update /chosen
  " /chosen" find-package if
    >r stdin @ encode-int " stdin" r> (property)
  then

[IFDEF] CONFIG_SPARC32
  \ update stdin-path properties
  \ (this isn't part of the IEEE1275 spec but needed by older Solaris)
  " /" find-package if
    >r stdin @ get-instance-path encode-string " stdin-path" r> (property)
  then
[THEN]
;

: output    ( dev-str dev-len -- )
  2dup find-dev 0= if
    ." Output device " type ."  not found." cr exit
  then

  " write" rot find-method 0= if
    type ."  has no write method." cr exit
  then
  drop
  
  \ open stdin device
  2dup open-dev ?dup 0= if
    ." Opening " type ."  failed." cr exit
  then
  -rot 2drop

  \ close old stdout
  stdout @ ?dup if close-dev then
  stdout !

  \ update /chosen
  " /chosen" find-package if
    >r stdout @ encode-int " stdout" r> (property)
  then

[IFDEF] CONFIG_SPARC32
  \ update stdout-path properties
  \ (this isn't part of the IEEE1275 spec but needed by older Solaris)
  " /" find-package if
    >r stdout @ get-instance-path encode-string " stdout-path" r> (property)
  then
[THEN]
;

: io    ( dev-str dev-len -- )
  2dup input output
;

\ key?, key and emit implementation
variable io-char
variable io-out-char

: io-key? ( -- available? )
  io-char @ -1 <> if true exit then
  io-char 1 " read" stdin @ $call-method
  1 =
;

: io-key ( -- key )
  \ poll for key
  begin io-key? until
  io-char c@ -1 to io-char
;

: io-emit ( char -- )
  stdout @ if
    io-out-char c!
    io-out-char 1 " write" stdout @ $call-method
  then
  drop
;

variable CONSOLE-IN-list
variable CONSOLE-OUT-list

: CONSOLE-IN-initializer ( xt -- )
  CONSOLE-IN-list list-add , 
;
: CONSOLE-OUT-initializer ( xt -- )
  CONSOLE-OUT-list list-add , 
;

: install-console    ( -- )
  
  \ create screen alias
  " /aliases" find-package if
    >r
    " screen" find-package if drop else
      \ bad (or missing) screen alias
      0 " display" iterate-device-type ?dup if
        ( display-ph R: alias-ph )
        get-package-path encode-string " screen" r@ (property)
      then
    then
    r> drop
  then

  output-device output
  input-device input

  \ let arch determine a useful output device
  CONSOLE-OUT-list begin list-get while
    stdout @ if drop else @ execute then
  repeat

  \ let arch determine a useful input device
  CONSOLE-IN-list begin list-get while
    stdin @ if drop else @ execute then
  repeat

  \ activate console
  stdout @ if
    ['] io-emit to emit
  then

  stdin @ if
    -1 to io-char
    ['] io-key? to key?
    ['] io-key to key  
  then
;

:noname
  " screen" output
; CONSOLE-OUT-initializer
