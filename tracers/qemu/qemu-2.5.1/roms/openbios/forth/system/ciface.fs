
0 value ciface-ph

dev /openprom/
new-device
" client-services" device-name

active-package to ciface-ph

\ -------------------------------------------------------------
\ private stuff
\ -------------------------------------------------------------

private

variable callback-function

: ?phandle ( phandle -- phandle )
  dup 0= if ." NULL phandle" -1 throw then
;
: ?ihandle ( ihandle -- ihandle )
  dup 0= if ." NULL ihandle" -2 throw then
;

\ copy and null terminate return string
: ci-strcpy ( buf buflen str len -- len )
  >r -rot dup
  ( str buf buflen buflen R: len )
  r@ min swap
  ( str buf n buflen R: len )
  over > if
    ( str buf n )
    2dup + 0 swap c!
  then
  move r>
;

0 value memory-ih
0 value mmu-ih

:noname ( -- )
  " /chosen" find-device

  " mmu" active-package get-package-property 0= if
    decode-int nip nip to mmu-ih
  then

  " memory" active-package get-package-property 0= if
    decode-int nip nip to memory-ih
  then
  device-end
; SYSTEM-initializer

: safetype
  ." <" dup cstrlen dup 20 < if type else 2drop ." BAD" then ." >"
;

: phandle-exists?  ( phandle -- found? )
  false swap 0
  begin iterate-tree ?dup while
    ( found? find-ph current-ph )
    over over = if
      rot drop true -rot
    then
  repeat
  drop
;

\ -------------------------------------------------------------
\ public interface
\ -------------------------------------------------------------

external

\ -------------------------------------------------------------
\ 6.3.2.1 Client interface
\ -------------------------------------------------------------

\ returns -1 if missing
: test ( name -- 0|-1 )
  dup cstrlen ciface-ph find-method
  if drop 0 else -1 then
;

\ -------------------------------------------------------------
\ 6.3.2.2 Device tree
\ -------------------------------------------------------------

: peer peer ;
: child child ;
: parent parent ;

: getproplen ( name phandle -- len|-1 )
  over cstrlen swap
  ?phandle get-package-property
  if -1 else nip then
;

: getprop ( buflen buf name phandle -- size|-1 )
  \ detect phandle == -1 
  dup -1 = if
    2drop 2drop -1 exit
  then

  \ return -1 if phandle is 0 (MacOS actually does this)
  ?dup 0= if drop 2drop -1 exit then
 
  over cstrlen swap
  ?phandle get-package-property if 2drop -1 exit then
  ( buflen buf prop proplen )
  >r swap rot r>
  ( prop buf buflen proplen )
  dup >r min move r>
;

\ 1 OK, 0 no more prop, -1 prev invalid
: nextprop ( buf prev phandle -- 1|0|-1 )
  >r
  dup 0= if 0 else dup cstrlen then

  ( buf prev prev_len )
  
  \ verify that prev exists (overkill...)
  dup if
    2dup r@ get-package-property if
      r> 2drop drop
      0 swap c!
      -1 exit
    else
      2drop
    then
  then
  
  ( buf prev prev_len )

  r> next-property if
    ( buf name name_len )
    dup 1+ -rot ci-strcpy drop 1
  else
    ( buf )
    0 swap c!
    0
  then
;

: setprop ( len buf name phandle -- size )
  3 pick >r
  >r >r swap encode-bytes  \ ( prop-addr prop-len  R: phandle name ) 
  r> dup cstrlen r>
  (property)
  r>
;

: finddevice ( dev_spec -- phandle|-1 )
  dup cstrlen
  \ ." FIND-DEVICE " 2dup type
  find-dev 0= if -1 then
  \ ." -- " dup . cr
;

: instance-to-package ( ihandle -- phandle )
  ?ihandle ihandle>phandle
;

: package-to-path ( buflen buf phandle -- length )
  \ XXX improve error checking
  dup 0= if 3drop -1 exit then
  >r swap r>
  get-package-path
  ( buf buflen str len )
  ci-strcpy
;

: canon ( buflen buf dev_specifier -- len )
  dup cstrlen find-dev if
    ( buflen buf phandle )
    package-to-path
  else
    2drop -1
  then
;

: instance-to-path ( buflen buf ihandle -- length )
  \ XXX improve error checking
  dup 0= if 3drop -1 exit then
  >r swap r>
  get-instance-path
  \ ." INSTANCE: " 2dup type cr dup .
  ( buf buflen str len )
  ci-strcpy
;

: instance-to-interposed-path ( buflen buf ihandle -- length )
  \ XXX improve error checking
  dup 0= if 3drop -1 exit then
  >r swap r>
  get-instance-interposed-path
  ( buf buflen str len )
  ci-strcpy
;

: call-method ( ihandle method -- xxxx catch-result )
  dup 0= if ." call of null method" -1 exit then
  dup >r
  dup cstrlen
  \ ." call-method " 2dup type cr
  rot ?ihandle ['] $call-method catch dup if
    \ not necessary an error but very useful for debugging...
    ." call-method " r@ dup cstrlen type ." : exception " dup . cr
  then
  r> drop
;


\ -------------------------------------------------------------
\ 6.3.2.3 Device I/O
\ -------------------------------------------------------------

: open ( dev_spec -- ihandle|0 )
  dup cstrlen open-dev
;

: close ( ihandle -- )
  close-dev
;

: read ( len addr ihandle -- actual )
  >r swap r>
  dup ihandle>phandle " read" rot find-method
  if swap call-package else 3drop -1 then
;

: write ( len addr ihandle -- actual )
  >r swap r>
  dup ihandle>phandle " write" rot find-method
  if swap call-package else 3drop -1 then
;

: seek ( pos_lo pos_hi ihandle -- status )
  dup ihandle>phandle " seek" rot find-method
  if swap call-package else 3drop -1 then
;


\ -------------------------------------------------------------
\ 6.3.2.4 Memory
\ -------------------------------------------------------------

: claim ( align size virt -- baseaddr|-1 )
  -rot swap
  ciface-ph " cif-claim" rot find-method
  if execute else 3drop -1 then
;

: release ( size virt -- )
  swap
  ciface-ph " cif-release" rot find-method
  if execute else 2drop -1 then
;

\ -------------------------------------------------------------
\ 6.3.2.5 Control transfer
\ -------------------------------------------------------------

: boot ( bootspec -- )
  ." BOOT"
;

: enter ( -- )
  ." ENTER"
;

\ exit ( -- ) is defined later (clashes with builtin exit)

: chain ( virt size entry args len -- )
  ." CHAIN"
;

\ -------------------------------------------------------------
\ 6.3.2.6 User interface
\ -------------------------------------------------------------

: interpret ( xxx cmdstring -- ??? catch-reult )
  dup cstrlen
  \ ." INTERPRETE: --- " 2dup type
  ['] evaluate catch dup if
    \ this is not necessary an error...
    ." interpret: exception " dup . ." caught" cr

    \ Force back to interpret state on error, otherwise the next call to
    \ interpret gets confused if the error occurred in compile mode
    0 state !
  then
  \ ." --- " cr
;

: set-callback ( newfunc -- oldfunc )
  callback-function @
  swap
  callback-function !
;

\ : set-symbol-lookup ( sym-to-value -- value-to-sym ) ;


\ -------------------------------------------------------------
\ 6.3.2.7 Time
\ -------------------------------------------------------------

: milliseconds ( -- ms )
  get-msecs
;

\ -------------------------------------------------------------
\ arch?
\ -------------------------------------------------------------

: start-cpu ( xxx xxx xxx --- )
  ." Start CPU unimplemented" cr
  3drop
;

\ -------------------------------------------------------------
\ special
\ -------------------------------------------------------------

: exit ( -- )
  ." EXIT"
  outer-interpreter
;

: test-method    ( cstring-method phandle -- missing? )
  swap dup cstrlen rot
  
  \ Check for incorrect phandle
  dup phandle-exists? false = if
    -1 throw
  then
  
  find-method 0= if -1 else drop 0 then
;

finish-device
device-end


\ -------------------------------------------------------------
\ entry point
\ -------------------------------------------------------------

: client-iface ( [args] name len -- [args] -1 | [rets] 0 )
  ciface-ph find-method 0= if -1 exit then
  catch ?dup if
    cr ." Unexpected client interface exception: " . -2 cr exit
  then
  0
;

: client-call-iface ( [args] name len -- [args] -1 | [rets] 0 )
  ciface-ph find-method 0= if -1 exit then
  execute
  0
;
