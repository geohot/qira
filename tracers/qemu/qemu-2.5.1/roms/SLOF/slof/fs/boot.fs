\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

0 VALUE load-size
0 VALUE go-entry
VARIABLE state-valid false state-valid !
CREATE go-args 2 cells allot go-args 2 cells erase

\ \\\\\\\\\\\\\\ Structure/Implementation Dependent Methods

: $bootargs
   bootargs 2@ ?dup IF
   ELSE s" diagnostic-mode?" evaluate and IF s" diag-file" evaluate
   ELSE s" boot-file" evaluate THEN THEN
;

: $bootdev ( -- device-name len )
   bootdevice 2@ dup IF s"  " $cat THEN
   s" diagnostic-mode?" evaluate IF
      s" diag-device" evaluate
   ELSE
      s" boot-device" evaluate
   THEN
   $cat \ prepend bootdevice setting from vpd-bootlist
   strdup
   ?dup 0= IF
      disable-watchdog
      drop true ABORT" No boot device!"
   THEN
;


\ \\\\\\\\\\\\\\ Implementation Independent Methods (Depend on Previous)
\ *
\ *
: set-boot-args ( str len -- ) dup IF strdup ELSE nip dup THEN bootargs 2! ;

: (set-boot-device) ( str len -- )
   ?dup IF 1+ strdup 1- ELSE drop 0 0 THEN bootdevice 2!
;

' (set-boot-device) to set-boot-device

: (add-boot-device) ( str len -- )	\ Concatenate " str" to "bootdevice"
   bootdevice 2@ ?dup IF $cat-space ELSE drop THEN set-boot-device
;

' (add-boot-device) to add-boot-device

0 value claim-list

: no-go ( -- ) -64 boot-exception-handler ABORT ;

defer go ( -- )

: go-32 ( -- )
   state-valid @ IF
      0 ciregs >r3 ! 0 ciregs >r4 !
      go-args 2@ go-entry start-elf client-data
      claim-list elf-release 0 to claim-list
   THEN
   -6d boot-exception-handler ABORT
;

: go-64 ( args len entry r2 -- )
    0 ciregs >r3 ! 0 ciregs >r4 !
    start-elf64 client-data
    claim-list elf-release 0 to claim-list
;

: set-le ( -- )
    1 ciregs >r13 !
;

: set-be ( -- )
    0 ciregs >r13 !
;

: go-64-be ( -- )
    state-valid @ IF
	set-be
	go-args 2@
	go-entry @
	go-entry 8 + @
	go-64
    THEN
    -6d boot-exception-handler ABORT
;


: go-32-be
    set-be
    go-32
;

: go-32-lev1
    set-le
    go-32
;

: go-64-lev1
    state-valid @ IF
	go-args 2@
	go-entry @ xbflip
	go-entry 8 + @ xbflip
	set-le
	go-64
    THEN
    -6d boot-exception-handler ABORT
;

: go-64-lev2
    state-valid @ IF
	go-args 2@
	go-entry 0
	set-le
	go-64
    THEN
    -6d boot-exception-handler ABORT
;

: load-elf-init ( arg len file-addr -- success )
   false state-valid !                            \ Not valid anymore ...
   claim-list IF                                    \ Release claimed mem
      claim-list elf-release 0 to claim-list        \ from last load
   THEN

   true swap -1                       ( arg len true file-addr -1 )
   elf-load-claim                     ( arg len true claim-list entry elftype )

   ( arg len true claim-list entry elftype )
   CASE
      1  OF ['] go-32-be   ENDOF           ( arg len true claim-list entry go )
      2  OF ['] go-64-be   ENDOF           ( arg len true claim-list entry go )
      3  OF ['] go-64-lev1 ENDOF           ( arg len true claim-list entry go )
      4  OF ['] go-64-lev2 ENDOF           ( arg len true claim-list entry go )
      5  OF ['] go-32-lev1 ENDOF           ( arg len true claim-list entry go )
      dup OF ['] no-go to go
         2drop 3drop false EXIT   ENDOF                   ( false )
   ENDCASE

   to go to go-entry to claim-list
   dup state-valid ! -rot

   2 pick IF
      go-args 2!
   ELSE
      2drop
   THEN
;

: init-program ( -- )
   $bootargs get-load-base ['] load-elf-init CATCH ?dup IF
      boot-exception-handler
      2drop 2drop false          \ Could not claim
   ELSE IF
         0 ciregs 2dup >r3 ! >r4 !  \ Valid (ELF ) Image
      THEN
   THEN
;


\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ Generic device load method:
\ *

: do-load ( devstr len -- img-size )	\ Device method wrapper
   use-load-watchdog? IF
      \ Set watchdog timer to 10 minutes, multiply with 2 because DHCP
      \ needs 1 second per try and add 1 min to avoid race conditions
      \ with watchdog timeout.
      4ec set-watchdog
   THEN
   my-self >r current-node @ >r         \ Save my-self
   ." Trying to load: " $bootargs type ."  from: " 2dup type ."  ... "
   2dup open-dev dup IF
      dup to my-self
      dup ihandle>phandle set-node
      -rot                              ( ihandle devstr len )
      encode-string s" bootpath" set-chosen
      $bootargs encode-string s" bootargs" set-chosen
      get-load-base s" load" 3 pick ['] $call-method CATCH IF
	-67 boot-exception-handler 3drop drop false
      ELSE
	 dup 0> IF
	    init-program
	 ELSE
	    false state-valid !
	    drop 0                                     \ Could not load
	 THEN
      THEN
      swap close-dev device-end dup to load-size
   ELSE -68 boot-exception-handler 3drop false THEN
   r> set-node r> to my-self                           \ Restore my-self
;

: parse-load ( "{devlist}" -- success )	\ Parse-execute boot-device list
   cr BEGIN parse-word dup WHILE
	 de-alias do-load dup 0< IF drop 0 THEN IF
	    state-valid @ IF ."   Successfully loaded" cr THEN
	    true 0d parse strdup load-list 2! EXIT
	 THEN
   REPEAT 2drop 0 0 load-list 2! false
;

: load ( "{params}<eol>"} -- success )	\ Client interface to load
   parse-word 0d parse -leading 2swap ?dup IF
      de-alias
      set-boot-device
   ELSE
      drop
   THEN
   set-boot-args s" parse-load " $bootdev $cat strdup evaluate
;

: load-next ( -- success )	\ Continue after go failed
   load-list 2@ ?dup IF s" parse-load " 2swap $cat strdup evaluate
   ELSE drop false THEN
;

\ \\\\\\\\\\\\\\\\\\\\\\\\\\
\ load/go utilities
\ -> Should be in loaders.fs

: noload false ;

' no-go to go

: (go-and-catch)  ( -- )
   \ Recommended Practice: Forth Source Support (scripts starting with comment)
   get-load-base c@ 5c =  get-load-base 1+ c@ 20 = AND IF
      load-size alloc-mem            ( allocated-addr )
      ?dup 0= IF ." alloc-mem failed." cr EXIT THEN
      load-size >r >r                ( R: allocate-addr load-size )
      get-load-base r@ load-size move    \ Move away from load-base
      r@ load-size evaluate          \ Run the script
      r> r> free-mem
      EXIT
   THEN
   \ Assume it's a normal executable, use "go" to run it:
   ['] go behavior CATCH IF -69 boot-exception-handler THEN
;


\ if the board does not get the bootlist from the nvram
\ then this word is supposed to be overloaded with the
\ word to get the bootlist from VPD (or from wheresoever)
read-bootlist

\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ IEEE 1275 : load (user interface)
\ *
: boot
   load 0= IF -65 boot-exception-handler EXIT THEN
   disable-watchdog (go-and-catch)
   BEGIN load-next WHILE
      disable-watchdog (go-and-catch)
   REPEAT

   \ When we return from boot print the banner again.
   .banner
;

: load load 0= IF -65 boot-exception-handler THEN ;

\ \\\\ Temporary hacks for backwards compatibility
: yaboot ." Use 'boot disk' instead " ;

: netboot ( -- rc ) ." Use 'boot net' instead " ;

: netboot-arg ( arg-string -- rc )
   s" boot net " 2swap $cat (parse-line) $cat
   evaluate
;

: netload ( -- rc ) (parse-line)
   load-base-override >r flash-load-base to load-base-override
   s" load net:" strdup 2swap $cat strdup evaluate
   r> to load-base-override
   load-size
;

: neteval ( -- ) FLASH-LOAD-BASE netload evaluate ;

